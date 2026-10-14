package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Hortlund/tunnl/internal/link"
	"github.com/Hortlund/tunnl/internal/protocol"
)

type tcpSession struct {
	port        int
	label       string
	tokenHash   string
	remote      string
	connectedAt time.Time
	conn        link.Conn
	listener    net.Listener
}

type tcpInfo struct {
	port        int
	label       string
	remote      string
	connectedAt time.Time
}

type tcpRegistry struct {
	mu       sync.RWMutex
	sessions map[int]*tcpSession
}

func newTCPRegistry() *tcpRegistry {
	return &tcpRegistry{sessions: make(map[int]*tcpSession)}
}

func (r *tcpRegistry) register(value *tcpSession) {
	r.mu.Lock()
	previous := r.sessions[value.port]
	r.sessions[value.port] = value
	r.mu.Unlock()
	if previous != nil && previous != value {
		if previous.listener != nil {
			_ = previous.listener.Close()
		}
		_ = previous.conn.CloseWithError(2, "tunnel replaced by a newer connection")
	}
}

func (r *tcpRegistry) unregister(value *tcpSession) {
	r.mu.Lock()
	if r.sessions[value.port] == value {
		delete(r.sessions, value.port)
	}
	r.mu.Unlock()
}

func (r *tcpRegistry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *tcpRegistry) snapshot() []tcpInfo {
	r.mu.RLock()
	values := make([]tcpInfo, 0, len(r.sessions))
	for _, value := range r.sessions {
		values = append(values, tcpInfo{port: value.port, label: value.label, remote: value.remote, connectedAt: value.connectedAt})
	}
	r.mu.RUnlock()
	return values
}

func (r *tcpRegistry) disconnectToken(tokenHash string) int {
	r.mu.Lock()
	var matches []*tcpSession
	for port, value := range r.sessions {
		if value.tokenHash == tokenHash {
			matches = append(matches, value)
			delete(r.sessions, port)
		}
	}
	r.mu.Unlock()
	for _, value := range matches {
		if value.listener != nil {
			_ = value.listener.Close()
		}
		_ = value.conn.CloseWithError(4, "client token revoked")
	}
	return len(matches)
}

// release frees a live reservation so the same token and label can bind it again.
func (r *tcpRegistry) release(port int, tokenHash, label string) bool {
	r.mu.Lock()
	value := r.sessions[port]
	if value == nil || value.tokenHash != tokenHash || value.label != label {
		r.mu.Unlock()
		return false
	}
	delete(r.sessions, port)
	r.mu.Unlock()
	if value.listener != nil {
		_ = value.listener.Close()
	}
	_ = value.conn.CloseWithError(2, "tunnel replaced by a newer connection")
	return true
}

func (r *tcpRegistry) closeAll() {
	r.mu.Lock()
	sessions := r.sessions
	r.sessions = make(map[int]*tcpSession)
	r.mu.Unlock()
	for _, value := range sessions {
		if value.listener != nil {
			_ = value.listener.Close()
		}
	}
}

func (s *Server) refuseTunnel(conn link.Conn, wire *protocol.Conn, message string) {
	_ = wire.WriteWelcome(protocol.Welcome{Error: message})
	s.rejectHandshake(conn, message)
}

func (s *Server) tcpRange() string {
	if s.config.TCPPortMin == 0 || s.config.TCPPortMax == 0 {
		return "disabled"
	}
	return fmt.Sprintf("%s:%d-%d", s.config.TCPBind, s.config.TCPPortMin, s.config.TCPPortMax)
}

func (s *Server) serveTCP(ctx context.Context, conn link.Conn, wire *protocol.Conn, control link.Stream, hello protocol.Hello) {
	if s.config.TCPPortMin == 0 || s.config.TCPPortMax == 0 {
		s.refuseTunnel(conn, wire, "tcp forwarding is not enabled")
		return
	}
	label := strings.TrimSpace(hello.Label)
	if label == "" || len(label) > 200 || strings.IndexFunc(label, unicode.IsControl) >= 0 {
		s.refuseTunnel(conn, wire, "tcp label is required")
		return
	}
	tokenHash := hashToken(hello.Token)
	listener, port, err := s.allocateTCP(ctx, tokenHash, label)
	if err != nil {
		s.refuseTunnel(conn, wire, err.Error())
		return
	}
	value := &tcpSession{
		port: port, label: label, tokenHash: tokenHash, remote: conn.RemoteAddr().String(),
		connectedAt: time.Now().UTC(), conn: conn, listener: listener,
	}
	s.tcpPorts.register(value)
	acceptDone := make(chan struct{})
	started := false
	defer func() {
		_ = listener.Close()
		if started {
			<-acceptDone
		}
		s.tcpPorts.unregister(value)
	}()

	publicHost := s.config.TCPPublicHost
	if publicHost == "" {
		publicHost = s.config.BaseDomain
	}
	publicURL := "tcp://" + net.JoinHostPort(publicHost, strconv.Itoa(port))
	if err := wire.WriteWelcome(protocol.Welcome{OK: true, URL: publicURL, Port: port}); err != nil {
		return
	}
	s.metrics.totalConnections.Add(1)
	s.logger.Info("tcp tunnel connected", "port", port, "label", label, "remote", conn.RemoteAddr().String(), "transport", conn.Transport())
	defer s.logger.Info("tcp tunnel disconnected", "port", port)

	started = true
	go func() {
		defer close(acceptDone)
		s.acceptTCP(ctx, conn, listener)
	}()

	for {
		_ = control.SetReadDeadline(time.Now().Add(s.config.HeartbeatTimeout))
		message, err := wire.ReadControl()
		if err != nil {
			return
		}
		if message.Type != "ping" {
			_ = conn.CloseWithError(1, "invalid control message")
			return
		}
	}
}

func (s *Server) allocateTCP(ctx context.Context, tokenHash, label string) (net.Listener, int, error) {
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()
	port, found, err := s.store.LookupTCP(ctx, tokenHash, label)
	if err != nil {
		return nil, 0, err
	}
	if found {
		listener, listenErr := s.listenTCP(port)
		if listenErr == nil {
			return listener, port, nil
		}
		if s.tcpPorts.release(port, tokenHash, label) {
			listener, listenErr = s.listenTCP(port)
			if listenErr == nil {
				return listener, port, nil
			}
		}
		if deleteErr := s.store.DeleteTCPPort(ctx, port); deleteErr != nil {
			return nil, 0, deleteErr
		}
	}
	count, err := s.store.CountTCP(ctx, tokenHash)
	if err != nil {
		return nil, 0, err
	}
	if s.config.MaxTCPPerToken >= 0 && count >= s.config.MaxTCPPerToken {
		return nil, 0, errors.New("tcp port limit reached")
	}
	reserved, err := s.store.TCPPorts(ctx)
	if err != nil {
		return nil, 0, err
	}
	for candidate := s.config.TCPPortMin; candidate <= s.config.TCPPortMax; candidate++ {
		if _, taken := reserved[candidate]; taken {
			continue
		}
		listener, listenErr := s.listenTCP(candidate)
		if listenErr != nil {
			continue
		}
		if saveErr := s.store.SaveTCP(ctx, candidate, tokenHash, label); saveErr != nil {
			_ = listener.Close()
			if strings.Contains(saveErr.Error(), "reserved") {
				continue
			}
			return nil, 0, saveErr
		}
		return listener, candidate, nil
	}
	return nil, 0, errors.New("no tcp ports available")
}

func (s *Server) listenTCP(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort(s.config.TCPBind, strconv.Itoa(port)))
}

func (s *Server) acceptTCP(ctx context.Context, conn link.Conn, listener net.Listener) {
	slots := make(chan struct{}, s.config.MaxTCPConnections)
	for {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		if !s.tcpAccepts.Allow(remoteIP(peer.RemoteAddr())) {
			s.metrics.tcpRejected.Add(1)
			_ = peer.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			s.metrics.tcpRejected.Add(1)
			_ = peer.Close()
			continue
		}
		s.metrics.tcpConnections.Add(1)
		go func() {
			defer func() { <-slots }()
			defer func() { _ = peer.Close() }()
			streamCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			stream, err := conn.OpenStreamSync(streamCtx)
			cancel()
			if err != nil {
				s.logger.Warn("open tcp tunnel stream", "error", err)
				return
			}
			defer func() { _ = stream.Close() }()
			splice(peer, stream)
		}()
	}
}

func splice(peer net.Conn, stream link.Stream) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(stream, peer)
		_ = stream.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(peer, stream)
		closeWrite(peer)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(conn net.Conn) {
	if writer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
		return
	}
	_ = conn.Close()
}
