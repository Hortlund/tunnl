package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
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
	"github.com/Hortlund/tunnl/internal/limit"
	"github.com/Hortlund/tunnl/internal/link"
	"github.com/Hortlund/tunnl/internal/names"
	"github.com/Hortlund/tunnl/internal/protocol"
	"github.com/Hortlund/tunnl/internal/store"
	"github.com/Hortlund/tunnl/internal/tlsutil"
)

var errTunnelOffline = errors.New("tunnel is offline")

type Config struct {
	HTTPAddr              string
	HTTPSAddr             string
	QUICAddr              string
	BaseDomain            string
	PublicPort            int
	Database              string
	AuthTokens            []string
	TrustProxyHeaders     bool
	HeartbeatTimeout      time.Duration
	TLSCert               string
	TLSKey                string
	ACMEEnabled           bool
	ACMEEmail             string
	ACMEStorage           string
	ACMEStaging           bool
	AdminAddr             string
	AdminToken            string
	AdminAllowRemote      bool
	CloudflareAPIToken    string
	Logger                *slog.Logger
	MetricsAddr           string
	MaxRequestBody        int64
	MaxResponseBody       int64
	RequestTimeout        time.Duration
	AcceptLimit           int
	AcceptWindow          time.Duration
	HandshakeFailureLimit int
	HandshakeWindow       time.Duration
	DisableWebSocket      bool
	TCPBind               string
	TCPPortMin            int
	TCPPortMax            int
	TCPPublicHost         string
	MaxTCPPerToken        int
	MaxTCPConnections     int
	TCPAcceptLimit        int
}

type Server struct {
	config            Config
	store             *store.Store
	registry          *registry
	metrics           *metrics
	logger            *slog.Logger
	admin             http.Handler
	certificateSource *tlsutil.Source
	accepts           *limit.Limiter
	handshakes        *limit.Limiter
	tcpAccepts        *limit.Limiter
	tcpPorts          *tcpRegistry
	tcpMu             sync.Mutex
	connsMu           sync.Mutex
	conns             map[link.Conn]struct{}
	tunnels           sync.WaitGroup
	runCtx            context.Context
}

func New(config Config) (*Server, error) {
	config.BaseDomain = strings.ToLower(strings.TrimSpace(config.BaseDomain))
	if err := validateBaseDomain(config.BaseDomain); err != nil {
		return nil, err
	}
	if config.Database == "" {
		return nil, errors.New("database is required")
	}
	if config.HTTPAddr == "" && config.HTTPSAddr == "" {
		return nil, errors.New("at least one HTTP listener is required")
	}
	if config.QUICAddr == "" {
		return nil, errors.New("QUIC address is required")
	}
	if config.MetricsAddr != "" {
		if _, _, err := net.SplitHostPort(config.MetricsAddr); err != nil {
			return nil, errors.New("metrics address must include a host and port")
		}
	}
	if config.MaxRequestBody == 0 {
		config.MaxRequestBody = 32 << 20
	}
	if config.MaxResponseBody == 0 {
		config.MaxResponseBody = 32 << 20
	}
	if config.MaxRequestBody < 0 || config.MaxResponseBody < 0 {
		return nil, errors.New("request and response body limits must be greater than zero")
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 2 * time.Minute
	}
	if config.RequestTimeout < 0 {
		return nil, errors.New("request timeout must be greater than zero")
	}
	if config.AcceptLimit == 0 {
		config.AcceptLimit = 30
	}
	if config.AcceptWindow <= 0 {
		config.AcceptWindow = time.Minute
	}
	if config.HandshakeFailureLimit == 0 {
		config.HandshakeFailureLimit = 20
	}
	if config.HandshakeWindow <= 0 {
		config.HandshakeWindow = time.Minute
	}
	if config.AcceptLimit < -1 || config.HandshakeFailureLimit < -1 {
		return nil, errors.New("rate limits must be -1 to disable or a positive count")
	}
	if config.TCPPortMin != 0 || config.TCPPortMax != 0 {
		span := config.TCPPortMax - config.TCPPortMin + 1
		if config.TCPPortMin < 1 || config.TCPPortMax > 65535 || span < 1 || span > 4096 {
			return nil, errors.New("tcp port range must be within 1-65535 and contain at most 4096 ports")
		}
		if config.TCPBind == "" {
			config.TCPBind = "0.0.0.0"
		}
	}
	if config.MaxTCPPerToken == 0 {
		config.MaxTCPPerToken = 4
	}
	if config.MaxTCPPerToken < -1 {
		return nil, errors.New("tcp port limit must be -1 to disable or a positive count")
	}
	if config.MaxTCPConnections == 0 {
		config.MaxTCPConnections = 64
	}
	if config.MaxTCPConnections < 1 {
		return nil, errors.New("tcp connection limit must be greater than zero")
	}
	if config.TCPAcceptLimit == 0 {
		config.TCPAcceptLimit = 60
	}
	if config.TCPAcceptLimit < -1 {
		return nil, errors.New("tcp accept limit must be -1 to disable or a positive count")
	}
	if config.ACMEEnabled {
		if config.TLSCert != "" || config.TLSKey != "" {
			return nil, errors.New("automatic ACME and manual TLS certificate files are mutually exclusive")
		}
		if config.ACMEEmail == "" {
			return nil, errors.New("ACME account email is required when automatic ACME is enabled")
		}
		if config.ACMEStorage == "" {
			return nil, errors.New("ACME storage path is required when automatic ACME is enabled")
		}
		if config.CloudflareAPIToken == "" {
			return nil, errors.New("Cloudflare API token is required for ACME DNS-01")
		}
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
	service := &Server{
		config:     config,
		store:      database,
		registry:   newRegistry(),
		metrics:    newMetrics(),
		logger:     config.Logger,
		accepts:    limit.New(config.AcceptLimit, config.AcceptWindow),
		handshakes: limit.New(config.HandshakeFailureLimit, config.HandshakeWindow),
		tcpAccepts: limit.New(config.TCPAcceptLimit, time.Minute),
		tcpPorts:   newTCPRegistry(),
		conns:      make(map[link.Conn]struct{}),
	}
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
	s.runCtx = ctx
	certificateSource, err := tlsutil.NewSource(ctx, tlsutil.Options{
		CertPath:           s.config.TLSCert,
		KeyPath:            s.config.TLSKey,
		BaseDomain:         s.config.BaseDomain,
		ACMEEnabled:        s.config.ACMEEnabled,
		ACMEEmail:          s.config.ACMEEmail,
		ACMEStorage:        s.config.ACMEStorage,
		ACMEStaging:        s.config.ACMEStaging,
		CloudflareAPIToken: s.config.CloudflareAPIToken,
	})
	if err != nil {
		return fmt.Errorf("configure TLS certificate: %w", err)
	}
	defer certificateSource.Close()
	s.certificateSource = certificateSource
	metricsCtx, stopMetrics := context.WithCancel(ctx)
	defer stopMetrics()
	s.metrics.sample(s.activeTunnels())
	go s.sampleMetrics(metricsCtx)
	if certificateSource.Generated() {
		s.logger.Warn("using an ephemeral self-signed development certificate")
	}
	if certificateSource.Managed() {
		s.logger.Info("automatic Let's Encrypt wildcard certificate management enabled", "domain", "*."+s.config.BaseDomain, "staging", s.config.ACMEStaging)
	}
	quicTLS := certificateSource.TLSConfig(tls.VersionTLS13, protocol.ALPN)
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
		servers = append(servers, &http.Server{Addr: s.config.HTTPSAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, TLSConfig: certificateSource.TLSConfig(tls.VersionTLS12)})
	}
	if s.config.AdminAddr != "" {
		servers = append(servers, &http.Server{Addr: s.config.AdminAddr, Handler: s.admin, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10})
	}
	if s.config.MetricsAddr != "" {
		servers = append(servers, &http.Server{Addr: s.config.MetricsAddr, Handler: s.metricsRoutes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10})
	}

	errorsChannel := make(chan error, len(servers)+1)
	acceptDone := make(chan struct{})
	go func() {
		err := s.acceptTunnels(ctx, listener)
		close(acceptDone)
		select {
		case errorsChannel <- err:
		default:
		}
	}()
	for _, httpServer := range servers {
		go func() {
			if httpServer.TLSConfig != nil {
				errorsChannel <- httpServer.ListenAndServeTLS("", "")
			} else {
				errorsChannel <- httpServer.ListenAndServe()
			}
		}()
	}

	s.logger.Info("tunnl server started", "http", s.config.HTTPAddr, "https", s.config.HTTPSAddr, "quic", s.config.QUICAddr, "admin", s.config.AdminAddr, "metrics", s.config.MetricsAddr, "base_domain", s.config.BaseDomain, "tcp", s.tcpRange(), "websocket", !s.config.DisableWebSocket)
	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = listener.Close()
		select {
		case <-acceptDone:
		case <-shutdownCtx.Done():
		}
		s.closeTracked()
		var group sync.WaitGroup
		for _, httpServer := range servers {
			httpServer.SetKeepAlivesEnabled(false)
			group.Add(1)
			go func(server *http.Server) { defer group.Done(); _ = server.Shutdown(shutdownCtx) }(httpServer)
		}
		group.Wait()
		done := make(chan struct{})
		go func() {
			s.tunnels.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-shutdownCtx.Done():
			s.logger.Warn("timed out waiting for tunnel sessions to finish")
		}
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

func (s *Server) sampleMetrics(ctx context.Context) {
	ticker := time.NewTicker(metricSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.metrics.sample(s.activeTunnels())
		}
	}
}

func (s *Server) acceptTunnels(ctx context.Context, listener *quic.Listener) error {
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		ip := remoteIP(conn.RemoteAddr())
		session := link.QUIC{Conn: conn}
		if !s.accepts.Allow(ip) || !s.handshakes.Permitted(ip) {
			s.metrics.rejectedAccepts.Add(1)
			_ = session.CloseWithError(1, "rate limited")
			continue
		}
		s.tunnels.Add(1)
		s.track(session)
		go func() {
			defer s.tunnels.Done()
			defer s.untrack(session)
			s.handleTunnel(ctx, session)
		}()
	}
}

func (s *Server) activeTunnels() int {
	return s.registry.count() + s.tcpPorts.count()
}

func (s *Server) track(conn link.Conn) {
	s.connsMu.Lock()
	s.conns[conn] = struct{}{}
	s.connsMu.Unlock()
}

func (s *Server) untrack(conn link.Conn) {
	s.connsMu.Lock()
	delete(s.conns, conn)
	s.connsMu.Unlock()
}

func (s *Server) closeTracked() {
	s.connsMu.Lock()
	conns := make([]link.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.connsMu.Unlock()
	s.tcpPorts.closeAll()
	for _, conn := range conns {
		_ = conn.CloseWithError(0, "server shutting down")
	}
}

func (s *Server) rejectHandshake(conn link.Conn, message string) {
	s.metrics.handshakeFailures.Add(1)
	s.handshakes.Allow(remoteIP(conn.RemoteAddr()))
	_ = conn.CloseWithError(1, message)
}

func (s *Server) handleTunnel(ctx context.Context, conn link.Conn) {
	defer func() { _ = conn.CloseWithError(0, "tunnel session ended") }()
	control, err := conn.AcceptStream(ctx)
	if err != nil {
		s.rejectHandshake(conn, "control stream required")
		return
	}
	wire := protocol.NewConn(control)
	_ = control.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, err := wire.ReadHello()
	if err != nil {
		s.rejectHandshake(conn, "invalid handshake")
		return
	}
	if hello.Version != protocol.Version {
		_ = wire.WriteWelcome(protocol.Welcome{Error: "incompatible protocol version"})
		s.rejectHandshake(conn, "incompatible protocol")
		return
	}
	if !s.authenticate(ctx, hello.Token) {
		_ = wire.WriteWelcome(protocol.Welcome{Error: "authentication failed"})
		s.rejectHandshake(conn, "authentication failed")
		return
	}
	switch hello.Mode {
	case "tcp":
		s.serveTCP(ctx, conn, wire, control, hello)
		return
	case "http":
	default:
		_ = wire.WriteWelcome(protocol.Welcome{Error: "unsupported tunnel mode"})
		s.rejectHandshake(conn, "unsupported mode")
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
		_ = wire.WriteWelcome(protocol.Welcome{Error: err.Error()})
		s.rejectHandshake(conn, "domain unavailable")
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
	if err := wire.WriteWelcome(protocol.Welcome{OK: true, Domain: domain, URL: publicURL}); err != nil {
		return
	}
	s.logger.Info("tunnel connected", "domain", domain, "remote", conn.RemoteAddr().String(), "transport", conn.Transport())
	defer s.logger.Info("tunnel disconnected", "domain", domain)

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
	mux.HandleFunc("GET /_tunnl/ready", s.ready)
	mux.HandleFunc("GET "+protocol.WebSocketPath, s.websocket)
	mux.HandleFunc("/", s.proxy)
	return mux
}

func (s *Server) metricsRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("GET /metrics", s.prometheus)
	return mux
}

func (s *Server) health(writer http.ResponseWriter, request *http.Request) {
	if !s.statusHost(request.Host) && request.URL.Path == "/_tunnl/health" {
		s.proxy(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(writer, `{"status":"ok","tunnels":%d}`+"\n", s.activeTunnels())
}

func (s *Server) ready(writer http.ResponseWriter, request *http.Request) {
	if !s.statusHost(request.Host) && request.URL.Path == "/_tunnl/ready" {
		s.proxy(writer, request)
		return
	}
	if err := s.store.Ping(request.Context()); err != nil {
		http.Error(writer, "not ready", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(writer, "{\"status\":\"ready\",\"tunnels\":%d}\n", s.activeTunnels())
}

func (s *Server) statusHost(hostport string) bool {
	host := hostWithoutPort(hostport)
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "status."+s.config.BaseDomain
}

func (s *Server) prometheus(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writePrometheus(writer, s.metrics, s.registry.count(), s.tcpPorts.count())
}

func (s *Server) proxy(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	recorder := &statusWriter{ResponseWriter: writer}
	s.metrics.totalRequests.Add(1)
	if s.config.RequestTimeout > 0 {
		ctx, cancel := context.WithTimeout(request.Context(), s.config.RequestTimeout)
		defer cancel()
		request = request.WithContext(ctx)
	}
	defer func() {
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		s.logger.Info("public request",
			"host", request.Host,
			"method", request.Method,
			"path", request.URL.Path,
			"status", status,
			"bytes", recorder.bytes,
			"duration", time.Since(started).String(),
			"remote", request.RemoteAddr,
		)
	}()
	if request.Header.Get("Upgrade") != "" {
		s.metrics.failedRequests.Add(1)
		http.Error(recorder, "protocol upgrades are not supported yet", http.StatusNotImplemented)
		return
	}
	host := hostWithoutPort(request.Host)
	suffix := "." + s.config.BaseDomain
	if !strings.HasSuffix(host, suffix) {
		s.metrics.failedRequests.Add(1)
		http.Error(recorder, "unknown tunnl host", http.StatusNotFound)
		return
	}
	domain := strings.TrimSuffix(host, suffix)
	if strings.Contains(domain, ".") {
		s.metrics.failedRequests.Add(1)
		http.Error(recorder, "invalid tunnl host", http.StatusNotFound)
		return
	}
	if s.config.MaxRequestBody > 0 && request.ContentLength > s.config.MaxRequestBody {
		s.metrics.failedRequests.Add(1)
		http.Error(recorder, "request body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if s.config.MaxRequestBody > 0 {
		request.Body = http.MaxBytesReader(nil, request.Body, s.config.MaxRequestBody)
	}
	streamCtx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	stream, err := s.registry.open(streamCtx, domain)
	if err != nil {
		s.metrics.failedRequests.Add(1)
		http.Error(recorder, "tunnel is offline", http.StatusBadGateway)
		return
	}
	defer stream.Close()
	_ = http.NewResponseController(recorder).EnableFullDuplex()
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
		http.Error(recorder, "tunnel response failed", http.StatusBadGateway)
		return
	}
	defer finishRequestWrite(request, stream, requestWrite)
	defer response.Body.Close()
	if s.config.MaxResponseBody > 0 && response.ContentLength > s.config.MaxResponseBody {
		s.metrics.failedRequests.Add(1)
		http.Error(recorder, "tunnel response too large", http.StatusBadGateway)
		return
	}
	copyHeaders(recorder.Header(), response.Header)
	recorder.Header().Set("Via", "tunnl")
	recorder.WriteHeader(response.StatusCode)
	body := io.Reader(response.Body)
	if s.config.MaxResponseBody > 0 {
		body = io.LimitReader(response.Body, s.config.MaxResponseBody+1)
	}
	written, err := io.Copy(recorder, body)
	s.metrics.responseBytes.Add(uint64(written))
	if s.config.MaxResponseBody > 0 && written > s.config.MaxResponseBody {
		s.metrics.failedRequests.Add(1)
		stream.CancelRead(3)
		s.logger.Warn("tunnel response exceeded the body limit", "domain", domain, "limit", s.config.MaxResponseBody)
		return
	}
	if err != nil {
		s.metrics.failedRequests.Add(1)
		s.logger.Debug("public response ended", "domain", domain, "error", err)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func validateBaseDomain(domain string) error {
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, "/:\\*? \t") {
		return errors.New("base domain must be a bare hostname")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return errors.New("base domain must contain at least two labels")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("base domain must be a bare hostname")
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return errors.New("base domain must be a bare hostname")
			}
		}
	}
	return nil
}

func finishRequestWrite(request *http.Request, stream link.Stream, writeDone <-chan error) {
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
