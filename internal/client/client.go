package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/Hortlund/tunnl/internal/protocol"
)

type Config struct {
	Server             string
	Token              string
	Domain             string
	Target             *url.URL
	HostHeader         string
	InsecureSkipVerify bool
	DisableState       bool
	Logger             *slog.Logger
	OnReady            func(protocol.Welcome)
}

type Client struct {
	config    Config
	transport *http.Transport
}

func New(config Config) (*Client, error) {
	if config.Server == "" || config.Token == "" || config.Target == nil {
		return nil, errors.New("server, token, and target are required")
	}
	if config.Target.Scheme != "http" && config.Target.Scheme != "https" {
		return nil, errors.New("target must use http or https")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Client{
		config: config,
		transport: &http.Transport{
			Proxy:                 nil,
			DisableCompression:    true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
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
	conn, err := quic.DialAddr(ctx, c.config.Server, tlsConfig, &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       45 * time.Second,
		KeepAlivePeriod:      15 * time.Second,
		MaxIncomingStreams:   1_000,
	})
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}
	defer conn.CloseWithError(0, "client stopped")

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	stateKey := c.config.Server + "|" + c.config.Target.String()
	domain := c.config.Domain
	if domain == "" && !c.config.DisableState {
		domain = loadDomain(stateKey)
	}
	if err := json.NewEncoder(control).Encode(protocol.Hello{
		Version: protocol.Version,
		Token:   c.config.Token,
		Domain:  domain,
		Mode:    "http",
	}); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}
	var welcome protocol.Welcome
	if err := json.NewDecoder(control).Decode(&welcome); err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}
	if !welcome.OK {
		return fmt.Errorf("relay rejected tunnel: %s", welcome.Error)
	}
	if !c.config.DisableState {
		if err := saveDomain(stateKey, welcome.Domain); err != nil {
			c.config.Logger.Warn("could not persist allocated domain", "error", err)
		}
	}
	if c.config.OnReady != nil {
		c.config.OnReady(welcome)
	}

	heartbeatDone := make(chan error, 1)
	go func() { heartbeatDone <- c.heartbeat(ctx, control) }()
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

func (c *Client) heartbeat(ctx context.Context, control *quic.Stream) error {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	encoder := json.NewEncoder(control)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := encoder.Encode(protocol.Control{Type: "ping"}); err != nil {
				return fmt.Errorf("send heartbeat: %w", err)
			}
		}
	}
}

func (c *Client) handleStream(stream *quic.Stream) {
	defer stream.Close()
	request, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		c.config.Logger.Warn("could not read tunneled request", "error", err)
		stream.CancelRead(1)
		return
	}
	defer request.Body.Close()
	request = request.WithContext(stream.Context())
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
