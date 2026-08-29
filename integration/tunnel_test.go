package integration_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hortlund/tunnl/internal/client"
	"github.com/Hortlund/tunnl/internal/protocol"
	"github.com/Hortlund/tunnl/internal/server"
)

func TestHTTPForwardingAndStableReservation(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Target", "reached")
		_, _ = io.WriteString(writer, "hello through tunnl: "+request.URL.Path)
	}))
	defer target.Close()

	httpAddr := freeTCPAddr(t)
	quicAddr := freeUDPAddr(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := server.New(server.Config{
		HTTPAddr:   httpAddr,
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
	waitForHealth(t, httpAddr)

	targetURL := targetURL(t, target.URL)
	clientCtx, stopClient := context.WithCancel(context.Background())
	ready := make(chan protocol.Welcome, 1)
	tunnel, err := client.New(client.Config{
		Server:             quicAddr,
		Token:              "integration-secret",
		Domain:             "stable-name",
		Target:             targetURL,
		InsecureSkipVerify: true,
		DisableState:       true,
		Logger:             logger,
		OnReady:            func(welcome protocol.Welcome) { ready <- welcome },
	})
	if err != nil {
		t.Fatal(err)
	}
	clientErrors := make(chan error, 1)
	go func() { clientErrors <- tunnel.Run(clientCtx) }()
	select {
	case welcome := <-ready:
		if welcome.Domain != "stable-name" {
			t.Fatalf("domain = %q, want stable-name", welcome.Domain)
		}
	case err := <-clientErrors:
		t.Fatalf("client stopped before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("client did not become ready")
	}

	request, err := http.NewRequest(http.MethodGet, "http://"+httpAddr+"/working", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "stable-name.tunnl.test"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "hello through tunnl: /working" || response.Header.Get("X-Target") != "reached" {
		t.Fatalf("unexpected response: status=%d header=%q body=%q", response.StatusCode, response.Header.Get("X-Target"), body)
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
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	listener.Close()
	return address
}

func waitForHealth(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get("http://" + address + "/_tunnl/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server health endpoint did not become ready")
}

func targetURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
