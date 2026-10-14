package server

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/Hortlund/tunnl/internal/mux"
	"github.com/Hortlund/tunnl/internal/wsock"
)

func (s *Server) websocket(writer http.ResponseWriter, request *http.Request) {
	host := hostWithoutPort(request.Host)
	if s.tunnelHost(host) {
		s.proxy(writer, request)
		return
	}
	if s.config.DisableWebSocket {
		http.NotFound(writer, request)
		return
	}
	if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") || strings.TrimSpace(request.Header.Get("Sec-WebSocket-Key")) == "" {
		http.Error(writer, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	ip := requestHost(request.RemoteAddr)
	if !s.accepts.Allow(ip) || !s.handshakes.Permitted(ip) {
		s.metrics.rejectedAccepts.Add(1)
		http.Error(writer, "rate limited", http.StatusTooManyRequests)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "websocket upgrade is unavailable", http.StatusInternalServerError)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		s.logger.Warn("websocket hijack failed", "error", err)
		return
	}
	defer func() { _ = conn.Close() }()
	socket, err := wsock.Accept(conn, buffered.Reader, buffered.Writer, request.Header.Get("Sec-WebSocket-Key"))
	if err != nil {
		s.logger.Warn("websocket accept failed", "error", err)
		return
	}
	session := mux.New(s.tunnelCtx(), mux.Server, wsock.Adapter{Conn: socket}, request.RemoteAddr)
	s.metrics.websocketSessions.Add(1)
	s.tunnels.Add(1)
	s.track(session)
	defer s.tunnels.Done()
	defer s.untrack(session)
	s.handleTunnel(s.tunnelCtx(), session)
}

func (s *Server) tunnelCtx() context.Context {
	if s.runCtx != nil {
		return s.runCtx
	}
	return context.Background()
}

func (s *Server) tunnelHost(host string) bool {
	suffix := "." + s.config.BaseDomain
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return false
	}
	switch label {
	case "admin", "api", "relay", "status", "tcp", "www":
		return false
	default:
		return true
	}
}

func requestHost(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return value
	}
	return host
}
