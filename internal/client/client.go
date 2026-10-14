package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/Hortlund/tunnl/internal/link"
	"github.com/Hortlund/tunnl/internal/mux"
	"github.com/Hortlund/tunnl/internal/protocol"
	"github.com/Hortlund/tunnl/internal/wsock"
)

type Config struct {
	Server                string
	Token                 string
	Domain                string
	Target                *url.URL
	HostHeader            string
	InsecureSkipVerify    bool
	DisableState          bool
	ResponseHeaderTimeout time.Duration
	Logger                *slog.Logger
	OnReady               func(protocol.Welcome)
	Mode                  string
	TCPAddress            string
	QUICDialTimeout       time.Duration
	WebSocketOnly         bool
	DisableWebSocket      bool
}

type Client struct {
	config    Config
	transport *http.Transport

	mu            sync.Mutex
	sessionCtx    context.Context
	transportName string
	preferWS      bool
}

func New(config Config) (*Client, error) {
	if config.Mode == "" {
		config.Mode = "http"
	}
	if config.WebSocketOnly && config.DisableWebSocket {
		return nil, errors.New("websocket-only and no-websocket cannot both be set")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.QUICDialTimeout <= 0 {
		config.QUICDialTimeout = 5 * time.Second
	}
	switch config.Mode {
	case "http":
		if config.Server == "" || config.Token == "" || config.Target == nil {
			return nil, errors.New("server, token, and target are required")
		}
		if config.Target.Scheme != "http" && config.Target.Scheme != "https" {
			return nil, errors.New("target must use http or https")
		}
	case "tcp":
		if config.Server == "" || config.Token == "" || config.TCPAddress == "" {
			return nil, errors.New("server, token, and tcp address are required")
		}
		if _, _, err := net.SplitHostPort(config.TCPAddress); err != nil {
			return nil, errors.New("tcp address must be host:port")
		}
	default:
		return nil, errors.New("tunnel mode must be http or tcp")
	}
	return &Client{
		config: config,
		transport: &http.Transport{
			Proxy:                 nil,
			DisableCompression:    true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		},
	}, nil
}

// EstablishedTransport reports the transport that completed the latest handshake.
func (c *Client) EstablishedTransport() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transportName
}

func (c *Client) Run(ctx context.Context) error {
	order := c.transportOrder()
	var quicErr error
	for index, transport := range order {
		err := c.runTransport(ctx, transport)
		if err == nil || ctx.Err() != nil || rejected(err) {
			return err
		}
		if transport == "quic" {
			quicErr = err
		}
		if index == len(order)-1 {
			if quicErr != nil && transport != "quic" {
				return fmt.Errorf("%w (quic failed: %w)", err, quicErr)
			}
			return err
		}
		if transport == "quic" {
			c.config.Logger.Warn("quic unavailable, udp may be blocked; trying websocket", "error", err)
		}
	}
	return quicErr
}

func (c *Client) transportOrder() []string {
	if c.config.WebSocketOnly {
		return []string{"websocket"}
	}
	if c.config.DisableWebSocket {
		return []string{"quic"}
	}
	c.mu.Lock()
	preferWS := c.preferWS
	c.mu.Unlock()
	if preferWS {
		return []string{"websocket", "quic"}
	}
	return []string{"quic", "websocket"}
}

func (c *Client) runTransport(ctx context.Context, transport string) error {
	var conn link.Conn
	var err error
	switch transport {
	case "quic":
		conn, err = c.dialQUIC(ctx)
	case "websocket":
		conn, err = c.dialWebSocket(ctx)
	default:
		return fmt.Errorf("unknown transport %q", transport)
	}
	if err != nil {
		return err
	}
	return c.serve(ctx, conn)
}

func (c *Client) dialQUIC(ctx context.Context) (link.Conn, error) {
	serverName := c.config.Server
	if host, _, err := net.SplitHostPort(c.config.Server); err == nil {
		serverName = host
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{protocol.ALPN},
		ServerName:         serverName,
		InsecureSkipVerify: c.config.InsecureSkipVerify, // Explicit development-only option.
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.config.QUICDialTimeout)
	conn, err := quic.DialAddr(dialCtx, c.config.Server, tlsConfig, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       45 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
		MaxIncomingStreams:   1_000,
	})
	cancel()
	if err != nil {
		return nil, fmt.Errorf("connect to relay over quic: %w", err)
	}
	return link.QUIC{Conn: conn}, nil
}

func (c *Client) dialWebSocket(ctx context.Context) (link.Conn, error) {
	host, port, err := net.SplitHostPort(c.config.Server)
	if err != nil {
		return nil, fmt.Errorf("relay address must be host:port: %w", err)
	}
	headerHost := host
	if port != "443" && port != "80" {
		headerHost = net.JoinHostPort(host, port)
	}
	var tlsConfig *tls.Config
	if port != "80" {
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         host,
			InsecureSkipVerify: c.config.InsecureSkipVerify,
		}
	}
	socket, err := wsock.Dial("tcp", c.config.Server, headerHost, protocol.WebSocketPath, tlsConfig, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to relay over websocket: %w", err)
	}
	if ctx.Err() != nil {
		_ = socket.Close()
		return nil, ctx.Err()
	}
	return mux.New(ctx, mux.Client, wsock.Adapter{Conn: socket}, c.config.Server), nil
}

func (c *Client) serve(ctx context.Context, conn link.Conn) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.mu.Lock()
	c.sessionCtx = sessionCtx
	c.mu.Unlock()
	defer func() { _ = conn.CloseWithError(0, "client stopped") }()

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	stateKey := c.stateKey()
	domain := c.config.Domain
	if c.config.Mode == "http" && domain == "" && !c.config.DisableState {
		domain = loadDomain(stateKey)
	}
	hello := protocol.Hello{Version: protocol.Version, Token: c.config.Token, Mode: c.config.Mode}
	if c.config.Mode == "tcp" {
		hello.Label = c.config.TCPAddress
	} else {
		hello.Domain = domain
	}
	wire := protocol.NewConn(control)
	if err := wire.WriteHello(hello); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}
	welcome, err := wire.ReadWelcome()
	if err != nil {
		if message, ok := applicationError(err); ok {
			return fmt.Errorf("relay rejected tunnel: %s", authHint(message))
		}
		return fmt.Errorf("read handshake: %w", err)
	}
	if !welcome.OK {
		return fmt.Errorf("relay rejected tunnel: %s", authHint(welcome.Error))
	}
	if c.config.Mode == "http" && !c.config.DisableState {
		if err := saveDomain(stateKey, welcome.Domain); err != nil {
			c.config.Logger.Warn("could not persist allocated domain", "error", err)
		}
	}
	c.mu.Lock()
	c.transportName = conn.Transport()
	c.preferWS = conn.Transport() == "websocket"
	c.mu.Unlock()
	if c.config.OnReady != nil {
		c.config.OnReady(welcome)
	}

	heartbeatDone := make(chan error, 1)
	go func() { heartbeatDone <- c.heartbeat(ctx, wire) }()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			select {
			case heartbeatErr := <-heartbeatDone:
				if heartbeatErr != nil && ctx.Err() == nil {
					return heartbeatErr
				}
			default:
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept tunnel stream: %w", err)
		}
		go c.handleStream(stream)
	}
}

func (c *Client) stateKey() string {
	if c.config.Mode == "tcp" {
		return c.config.Server + "|tcp|" + c.config.TCPAddress
	}
	return c.config.Server + "|" + c.config.Target.String()
}

func rejected(err error) bool {
	return err != nil && strings.Contains(err.Error(), "relay rejected tunnel")
}

func authHint(message string) string {
	if strings.Contains(strings.ToLower(message), "authentication") {
		return message + "; check TUNNL_TOKEN or run tunnld admin tokens create"
	}
	return message
}

func applicationError(err error) (string, bool) {
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) || appErr.ErrorCode == 0 {
		return "", false
	}
	if appErr.ErrorMessage != "" {
		return appErr.ErrorMessage, true
	}
	return err.Error(), true
}

func (c *Client) heartbeat(ctx context.Context, wire *protocol.Conn) error {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := wire.WriteControl(protocol.Control{Type: "ping"}); err != nil {
				return fmt.Errorf("send heartbeat: %w", err)
			}
		}
	}
}

func (c *Client) handleStream(stream link.Stream) {
	defer func() { _ = stream.Close() }()
	if c.config.Mode == "tcp" {
		c.handleTCP(stream)
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		c.config.Logger.Warn("could not read tunneled request", "error", err)
		stream.CancelRead(1)
		return
	}
	defer request.Body.Close()
	c.mu.Lock()
	sessionCtx := c.sessionCtx
	c.mu.Unlock()
	if sessionCtx == nil {
		sessionCtx = context.Background()
	}
	request = request.WithContext(sessionCtx)
	request.RequestURI = ""
	request.URL.Scheme = c.config.Target.Scheme
	request.URL.Host = c.config.Target.Host
	request.URL.Path = joinURLPath(c.config.Target.Path, request.URL.Path)
	if c.config.HostHeader != "" {
		request.Host = c.config.HostHeader
	} else {
		request.Host = c.config.Target.Host
	}
	request.Close = false

	response, err := c.transport.RoundTrip(request)
	if err != nil {
		c.config.Logger.Warn("local service request failed", "target", c.config.Target.Redacted(), "error", err)
		writeErrorResponse(stream, http.StatusBadGateway, "local service unavailable")
		return
	}
	defer response.Body.Close()
	if err := response.Write(stream); err != nil && !errors.Is(err, io.EOF) {
		c.config.Logger.Debug("tunnel response ended", "error", err)
	}
}

func (c *Client) handleTCP(stream link.Stream) {
	local, err := net.DialTimeout("tcp", c.config.TCPAddress, 10*time.Second)
	if err != nil {
		c.config.Logger.Warn("local tcp dial failed", "address", c.config.TCPAddress, "error", err)
		stream.CancelWrite(1)
		return
	}
	defer func() { _ = local.Close() }()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(stream, local)
		_ = stream.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(local, stream)
		if writer, ok := local.(interface{ CloseWrite() error }); ok {
			_ = writer.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func joinURLPath(base, requestPath string) string {
	if base == "" || base == "/" {
		return requestPath
	}
	joined := path.Join(base, requestPath)
	if strings.HasSuffix(requestPath, "/") && !strings.HasSuffix(joined, "/") {
		joined += "/"
	}
	return joined
}

func writeErrorResponse(writer io.Writer, status int, message string) {
	response := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(message + "\n")),
		ContentLength: int64(len(message) + 1),
	}
	response.Header.Set("Content-Type", "text/plain; charset=utf-8")
	_ = response.Write(writer)
}
