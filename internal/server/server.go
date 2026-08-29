package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/Hortlund/tunnl/internal/admin"
	"github.com/Hortlund/tunnl/internal/names"
	"github.com/Hortlund/tunnl/internal/protocol"
	"github.com/Hortlund/tunnl/internal/store"
	"github.com/Hortlund/tunnl/internal/tlsutil"
)

var errTunnelOffline = errors.New("tunnel is offline")

type Config struct {
	HTTPAddr           string
	HTTPSAddr          string
	QUICAddr           string
	BaseDomain         string
	PublicPort         int
	Database           string
	AuthTokens         []string
	TrustProxyHeaders  bool
	HeartbeatTimeout   time.Duration
	TLSCert            string
	TLSKey             string
	AdminAddr          string
	AdminToken         string
	AdminAllowRemote   bool
	CloudflareAPIToken string
	Logger             *slog.Logger
}

type Server struct {
	config   Config
	store    *store.Store
	registry *registry
	metrics  *metrics
	logger   *slog.Logger
	admin    http.Handler
}

func New(config Config) (*Server, error) {
	if config.BaseDomain == "" || config.Database == "" {
		return nil, errors.New("base domain and database are required")
	}
	if config.HTTPAddr == "" && config.HTTPSAddr == "" {
		return nil, errors.New("at least one HTTP listener is required")
	}
	if config.QUICAddr == "" {
		return nil, errors.New("QUIC address is required")
	}
	if config.AdminAddr != "" && !config.AdminAllowRemote {
		host, _, err := net.SplitHostPort(config.AdminAddr)
		if err != nil {
			return nil, errors.New("admin address must include a host and port")
		}
		if host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
			return nil, errors.New("admin listener must bind to loopback unless --admin-allow-remote is set")
		}
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.HeartbeatTimeout <= 0 {
		config.HeartbeatTimeout = 40 * time.Second
	}
	database, err := store.Open(config.Database)
	if err != nil {
		return nil, err
	}
	managedTokens, err := database.CountClientTokens(context.Background())
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("count client tokens: %w", err)
	}
	if len(config.AuthTokens) == 0 && managedTokens == 0 && config.AdminAddr == "" {
		database.Close()
		return nil, errors.New("at least one client token or an enabled admin listener is required")
	}
	service := &Server{config: config, store: database, registry: newRegistry(), metrics: newMetrics(), logger: config.Logger}
	if config.AdminAddr != "" {
		handler, err := admin.NewHandler(config.AdminToken, service, config.Logger)
		if err != nil {
			database.Close()
			return nil, fmt.Errorf("configure admin listener: %w", err)
		}
		service.admin = handler.Routes()
	}
	return service, nil
}

func (s *Server) Close() error { return s.store.Close() }

func (s *Server) Run(ctx context.Context) error {
	certificate, generated, err := tlsutil.LoadOrGenerate(s.config.TLSCert, s.config.TLSKey, s.config.BaseDomain)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	if generated {
		s.logger.Warn("using an ephemeral self-signed development certificate")
	}
	quicTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{protocol.ALPN}}
	listener, err := quic.ListenAddr(s.config.QUICAddr, quicTLS, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       45 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
		MaxIncomingStreams:   10,
	})
	if err != nil {
		return fmt.Errorf("listen for QUIC tunnels: %w", err)
	}
	defer listener.Close()

	handler := s.routes()
	var servers []*http.Server
	if s.config.HTTPAddr != "" {
		servers = append(servers, &http.Server{Addr: s.config.HTTPAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second})
	}
	if s.config.HTTPSAddr != "" {
		servers = append(servers, &http.Server{Addr: s.config.HTTPSAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}})
	}
	if s.config.AdminAddr != "" {
		servers = append(servers, &http.Server{Addr: s.config.AdminAddr, Handler: s.admin, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10})
	}

	errorsChannel := make(chan error, len(servers)+1)
	go func() { errorsChannel <- s.acceptTunnels(ctx, listener) }()
	for _, httpServer := range servers {
		httpServer := httpServer
		go func() {
			if httpServer.TLSConfig != nil {
				errorsChannel <- httpServer.ListenAndServeTLS("", "")
			} else {
				errorsChannel <- httpServer.ListenAndServe()
			}
		}()
	}

	s.logger.Info("tunnl server started", "http", s.config.HTTPAddr, "https", s.config.HTTPSAddr, "quic", s.config.QUICAddr, "admin", s.config.AdminAddr, "base_domain", s.config.BaseDomain)
	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		var group sync.WaitGroup
		for _, httpServer := range servers {
			group.Add(1)
			go func(server *http.Server) { defer group.Done(); _ = server.Shutdown(shutdownCtx) }(httpServer)
		}
		_ = listener.Close()
		group.Wait()
	}
	select {
	case <-ctx.Done():
		shutdown()
		return nil
	case runErr := <-errorsChannel:
		shutdown()
		if errors.Is(runErr, http.ErrServerClosed) || ctx.Err() != nil {
			return nil
		}
		return runErr
	}
}

func (s *Server) acceptTunnels(ctx context.Context, listener *quic.Listener) error {
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleTunnel(ctx, conn)
	}
}

func (s *Server) handleTunnel(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "tunnel session ended")
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "control stream required")
		return
	}
	decoder := json.NewDecoder(control)
	encoder := json.NewEncoder(control)
	_ = control.SetReadDeadline(time.Now().Add(10 * time.Second))
	var hello protocol.Hello
	if err := decoder.Decode(&hello); err != nil {
		_ = conn.CloseWithError(1, "invalid handshake")
		return
	}
	if hello.Version != protocol.Version {
		_ = encoder.Encode(protocol.Welcome{Error: "incompatible protocol version"})
		_ = conn.CloseWithError(1, "incompatible protocol")
		return
	}
	if !s.authenticate(ctx, hello.Token) {
		_ = encoder.Encode(protocol.Welcome{Error: "authentication failed"})
		_ = conn.CloseWithError(1, "authentication failed")
		return
	}
	if hello.Mode != "http" {
		_ = encoder.Encode(protocol.Welcome{Error: "unsupported tunnel mode"})
		_ = conn.CloseWithError(1, "unsupported mode")
		return
	}

	tokenHash := hashToken(hello.Token)
	domain := hello.Domain
	if domain == "" {
		domain, err = s.store.Allocate(ctx, tokenHash)
	} else {
		domain, err = names.Normalize(domain)
		if err == nil {
			err = s.store.Reserve(ctx, domain, tokenHash)
		}
	}
	if err != nil {
		_ = encoder.Encode(protocol.Welcome{Error: err.Error()})
		_ = conn.CloseWithError(1, "domain unavailable")
		return
	}

	value := &session{domain: domain, tokenHash: tokenHash, remote: conn.RemoteAddr().String(), connectedAt: time.Now().UTC(), conn: conn}
	s.registry.register(value)
	s.metrics.totalConnections.Add(1)
	defer s.registry.unregister(value)
	publicURL := "https://" + domain + "." + s.config.BaseDomain
	if s.config.PublicPort != 0 && s.config.PublicPort != 443 {
		publicURL += fmt.Sprintf(":%d", s.config.PublicPort)
	}
	if err := encoder.Encode(protocol.Welcome{OK: true, Domain: domain, URL: publicURL}); err != nil {
		return
	}
	s.logger.Info("tunnel connected", "domain", domain, "remote", conn.RemoteAddr())
	defer s.logger.Info("tunnel disconnected", "domain", domain)

	for {
		_ = control.SetReadDeadline(time.Now().Add(s.config.HeartbeatTimeout))
		var message protocol.Control
		if err := decoder.Decode(&message); err != nil {
			return
		}
		if message.Type != "ping" {
			_ = conn.CloseWithError(1, "invalid control message")
			return
		}
	}
}

func (s *Server) authenticate(ctx context.Context, token string) bool {
	valid := 0
	for _, candidate := range s.config.AuthTokens {
		if constantTimeEqual(token, candidate) {
			valid = 1
		}
	}
	if valid == 0 {
		matched, err := s.store.AuthenticateClientToken(ctx, hashToken(token))
		if err != nil {
			s.logger.Error("authenticate managed client token", "error", err)
		} else if matched {
			valid = 1
		}
	}
	return valid == 1
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_tunnl/health", s.health)
	mux.HandleFunc("/", s.proxy)
	return mux
}

func (s *Server) health(writer http.ResponseWriter, request *http.Request) {
	host := hostWithoutPort(request.Host)
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && host != "status."+strings.ToLower(s.config.BaseDomain) {
		s.proxy(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(writer, `{"status":"ok","tunnels":%d}`+"\n", s.registry.count())
}

func (s *Server) proxy(writer http.ResponseWriter, request *http.Request) {
	s.metrics.totalRequests.Add(1)
	if request.Header.Get("Upgrade") != "" {
		s.metrics.failedRequests.Add(1)
		http.Error(writer, "protocol upgrades are not supported yet", http.StatusNotImplemented)
		return
	}
	host := hostWithoutPort(request.Host)
	suffix := "." + s.config.BaseDomain
	if !strings.HasSuffix(strings.ToLower(host), suffix) {
		s.metrics.failedRequests.Add(1)
		http.Error(writer, "unknown tunnl host", http.StatusNotFound)
		return
	}
	domain := strings.TrimSuffix(strings.ToLower(host), suffix)
	if strings.Contains(domain, ".") {
		s.metrics.failedRequests.Add(1)
		http.Error(writer, "invalid tunnl host", http.StatusNotFound)
		return
	}
	streamCtx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	stream, err := s.registry.open(streamCtx, domain)
	if err != nil {
		s.metrics.failedRequests.Add(1)
		http.Error(writer, "tunnel is offline", http.StatusBadGateway)
		return
	}
	defer stream.Close()
	_ = http.NewResponseController(writer).EnableFullDuplex()
	requestFinished := make(chan struct{})
	defer close(requestFinished)
	go func() {
		select {
		case <-request.Context().Done():
			stream.CancelRead(3)
			stream.CancelWrite(3)
		case <-requestFinished:
		}
	}()

	outgoing := request.Clone(request.Context())
	outgoing.RequestURI = ""
	removeHopByHopHeaders(outgoing.Header)
	addForwardingHeaders(outgoing, s.config.TrustProxyHeaders)

	requestWrite := make(chan error, 1)
	go func() { requestWrite <- outgoing.Write(stream) }()
	response, err := http.ReadResponse(bufio.NewReader(stream), outgoing)
	if err != nil {
		s.metrics.failedRequests.Add(1)
		finishRequestWrite(request, stream, requestWrite)
		http.Error(writer, "tunnel response failed", http.StatusBadGateway)
		return
	}
	defer finishRequestWrite(request, stream, requestWrite)
	defer response.Body.Close()
	copyHeaders(writer.Header(), response.Header)
	writer.Header().Set("Via", "tunnl")
	writer.WriteHeader(response.StatusCode)
	written, err := io.Copy(writer, response.Body)
	s.metrics.responseBytes.Add(uint64(written))
	if err != nil {
		s.metrics.failedRequests.Add(1)
		s.logger.Debug("public response ended", "domain", domain, "error", err)
	}
}

func finishRequestWrite(request *http.Request, stream *quic.Stream, writeDone <-chan error) {
	select {
	case <-writeDone:
		return
	default:
	}
	stream.CancelWrite(3)
	_ = request.Body.Close()
	<-writeDone
}

func hostWithoutPort(value string) string {
	host := strings.ToLower(value)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return strings.TrimSuffix(host, ".")
}

func addForwardingHeaders(request *http.Request, trustIncoming bool) {
	clientIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		if existing := request.Header.Get("X-Forwarded-For"); trustIncoming && existing != "" {
			request.Header.Set("X-Forwarded-For", existing+", "+clientIP)
		} else {
			request.Header.Set("X-Forwarded-For", clientIP)
		}
	}
	if !trustIncoming {
		request.Header.Del("Forwarded")
		request.Header.Del("X-Real-IP")
	}
	request.Header.Set("X-Forwarded-Host", request.Host)
	if request.TLS != nil {
		request.Header.Set("X-Forwarded-Proto", "https")
	} else {
		request.Header.Set("X-Forwarded-Proto", "http")
	}
}

func copyHeaders(destination, source http.Header) {
	cleaned := source.Clone()
	removeHopByHopHeaders(cleaned)
	for key, values := range cleaned {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(headers http.Header) {
	for _, connection := range headers.Values("Connection") {
		for _, name := range strings.Split(connection, ",") {
			if name = strings.TrimSpace(name); name != "" {
				headers.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		headers.Del(name)
	}
}

func constantTimeEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
