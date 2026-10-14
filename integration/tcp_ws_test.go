package integration_test

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Hortlund/tunnl/internal/client"
	"github.com/Hortlund/tunnl/internal/protocol"
	"github.com/Hortlund/tunnl/internal/server"
)

func TestTCPForwarding(t *testing.T) {
	echo := startEcho(t)
	httpAddr := freeTCPAddr(t)
	quicAddr := freeUDPAddr(t)
	portMin, portMax := freePortRange(t, 8)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := server.New(server.Config{
		HTTPAddr:       httpAddr,
		QUICAddr:       quicAddr,
		BaseDomain:     "tunnl.test",
		Database:       filepath.Join(t.TempDir(), "tunnl.db"),
		AuthTokens:     []string{"integration-secret"},
		Logger:         logger,
		TCPBind:        "127.0.0.1",
		TCPPortMin:     portMin,
		TCPPortMax:     portMax,
		TCPPublicHost:  "127.0.0.1",
		MaxTCPPerToken: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- service.Run(serverCtx) }()
	waitForHealth(t, httpAddr)

	clientCtx, stopClient := context.WithCancel(context.Background())
	welcome := runTCPClient(t, clientCtx, logger, quicAddr, echo, false)
	exchangeTCP(t, "127.0.0.1", welcome.Port, []byte("ping-through-tcp"))

	limitedCtx, stopLimited := context.WithCancel(context.Background())
	defer stopLimited()
	limited, err := client.New(client.Config{
		Server:             quicAddr,
		Token:              "integration-secret",
		Mode:               "tcp",
		TCPAddress:         "127.0.0.1:1",
		InsecureSkipVerify: true,
		DisableState:       true,
		DisableWebSocket:   true,
		Logger:             logger,
		QUICDialTimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	limitedErr := make(chan error, 1)
	go func() { limitedErr <- limited.Run(limitedCtx) }()
	select {
	case err := <-limitedErr:
		if err == nil || !strings.Contains(err.Error(), "relay rejected tunnel") || !strings.Contains(err.Error(), "tcp port limit reached") {
			t.Fatalf("limit error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second tcp tunnel was not rejected")
	}

	stopClient()
	time.Sleep(100 * time.Millisecond)
	reuseCtx, stopReuse := context.WithCancel(context.Background())
	reused := runTCPClient(t, reuseCtx, logger, quicAddr, echo, false)
	if reused.Port != welcome.Port {
		t.Fatalf("reconnected port = %d, want %d", reused.Port, welcome.Port)
	}
	exchangeTCP(t, "127.0.0.1", reused.Port, []byte("again"))
	stopReuse()
	time.Sleep(100 * time.Millisecond)

	stopServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestWebSocketFallbackProxiesHTTP(t *testing.T) {
	local := startHTTP(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Target", "reached")
		_, _ = io.WriteString(writer, "ws-fallback "+request.URL.Path)
	}))
	httpAddr := freeTCPAddr(t)
	httpsAddr := freeTCPAddr(t)
	quicAddr := freeUDPAddr(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := server.New(server.Config{
		HTTPAddr:   httpAddr,
		HTTPSAddr:  httpsAddr,
		QUICAddr:   quicAddr,
		BaseDomain: "tunnl.test",
		PublicPort: 443,
		Database:   filepath.Join(t.TempDir(), "tunnl.db"),
		AuthTokens: []string{"integration-secret"},
		Logger:     logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- service.Run(serverCtx) }()
	waitForTLS(t, httpsAddr)

	clientCtx, stopClient := context.WithCancel(context.Background())
	ready := make(chan protocol.Welcome, 1)
	tunnel, err := client.New(client.Config{
		Server:             httpsAddr,
		Token:              "integration-secret",
		Domain:             "ws-demo",
		Target:             targetURL(t, local),
		InsecureSkipVerify: true,
		DisableState:       true,
		Logger:             logger,
		QUICDialTimeout:    2 * time.Second,
		OnReady:            func(welcome protocol.Welcome) { ready <- welcome },
	})
	if err != nil {
		t.Fatal(err)
	}
	clientErrors := make(chan error, 1)
	go func() { clientErrors <- tunnel.Run(clientCtx) }()
	select {
	case welcome := <-ready:
		if welcome.Domain != "ws-demo" {
			t.Fatalf("domain = %q", welcome.Domain)
		}
	case err := <-clientErrors:
		t.Fatalf("client stopped: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("websocket fallback did not become ready")
	}
	if got := tunnel.EstablishedTransport(); got != "websocket" {
		t.Fatalf("transport = %q, want websocket", got)
	}

	httpClient := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	request, err := http.NewRequest(http.MethodGet, "http://"+httpAddr+"/via-ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "ws-demo.tunnl.test"
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ws-fallback /via-ws" {
		t.Fatalf("proxied response = %d %q", response.StatusCode, body)
	}

	wsRequest, err := http.NewRequest(http.MethodGet, "http://"+httpAddr+"/_tunnl/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	wsRequest.Host = "ws-demo.tunnl.test"
	wsResponse, err := httpClient.Do(wsRequest)
	if err != nil {
		t.Fatal(err)
	}
	wsBody, err := io.ReadAll(wsResponse.Body)
	wsResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if wsResponse.StatusCode != http.StatusOK || string(wsBody) != "ws-fallback /_tunnl/ws" {
		t.Fatalf("tunnel host websocket path = %d %q", wsResponse.StatusCode, wsBody)
	}

	stopClient()
	select {
	case err := <-clientErrors:
		if err != nil {
			t.Fatalf("client shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not stop")
	}
	stopServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestTCPOverWebSocket(t *testing.T) {
	echo := startEcho(t)
	httpsAddr := freeTCPAddr(t)
	quicAddr := freeUDPAddr(t)
	portMin, portMax := freePortRange(t, 4)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := server.New(server.Config{
		HTTPSAddr:     httpsAddr,
		QUICAddr:      quicAddr,
		BaseDomain:    "tunnl.test",
		Database:      filepath.Join(t.TempDir(), "tunnl.db"),
		AuthTokens:    []string{"integration-secret"},
		Logger:        logger,
		TCPBind:       "127.0.0.1",
		TCPPortMin:    portMin,
		TCPPortMax:    portMax,
		TCPPublicHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- service.Run(serverCtx) }()
	waitForTLS(t, httpsAddr)

	clientCtx, stopClient := context.WithCancel(context.Background())
	welcome := runTCPClient(t, clientCtx, logger, httpsAddr, echo, true)
	exchangeTCP(t, "127.0.0.1", welcome.Port, []byte("tcp-over-ws"))
	stopClient()
	time.Sleep(100 * time.Millisecond)
	stopServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("server did not stop")
	}
}

func runTCPClient(t *testing.T, ctx context.Context, logger *slog.Logger, serverAddr, target string, websocketOnly bool) protocol.Welcome {
	t.Helper()
	ready := make(chan protocol.Welcome, 1)
	tunnel, err := client.New(client.Config{
		Server:             serverAddr,
		Token:              "integration-secret",
		Mode:               "tcp",
		TCPAddress:         target,
		InsecureSkipVerify: true,
		DisableState:       true,
		WebSocketOnly:      websocketOnly,
		DisableWebSocket:   !websocketOnly,
		Logger:             logger,
		QUICDialTimeout:    2 * time.Second,
		OnReady:            func(welcome protocol.Welcome) { ready <- welcome },
	})
	if err != nil {
		t.Fatal(err)
	}
	errors := make(chan error, 1)
	go func() { errors <- tunnel.Run(ctx) }()
	select {
	case welcome := <-ready:
		if welcome.Port == 0 {
			t.Fatal("welcome missing port")
		}
		if websocketOnly && tunnel.EstablishedTransport() != "websocket" {
			t.Fatalf("transport = %q, want websocket", tunnel.EstablishedTransport())
		}
		return welcome
	case err := <-errors:
		t.Fatalf("tcp client stopped: %v", err)
	case <-time.After(15 * time.Second):
		t.Fatal("tcp client did not become ready")
	}
	return protocol.Welcome{}
}

func startEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func startHTTP(t *testing.T, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: handler}
	go func() { _ = httpServer.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	})
	return "http://" + listener.Addr().String()
}

func exchangeTCP(t *testing.T, host string, port int, payload []byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if writer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func freePortRange(t *testing.T, span int) (int, int) {
	t.Helper()
	for base := 20000; base < 60000; base += span {
		listeners := make([]net.Listener, 0, span)
		ok := true
		for port := base; port < base+span; port++ {
			listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				ok = false
				break
			}
			listeners = append(listeners, listener)
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		if ok {
			return base, base + span - 1
		}
	}
	t.Fatal("no free tcp port range")
	return 0, 0
}

func waitForTLS(t *testing.T, address string) {
	t.Helper()
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := httpClient.Get("https://" + address + "/_tunnl/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("https health endpoint did not become ready")
}
