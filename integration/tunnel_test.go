package integration_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hortlund/tunnl/internal/client"
	"github.com/Hortlund/tunnl/internal/protocol"
	"github.com/Hortlund/tunnl/internal/server"
)

func TestHTTPForwardingAndStableReservation(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Target", "reached")
		writer.Header().Set("X-Seen-Forwarded-For", request.Header.Get("X-Forwarded-For"))
		if request.URL.Path == "/reject-upload" {
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = io.WriteString(writer, "rejected")
			return
		}
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
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
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
	if got := response.Header.Get("X-Seen-Forwarded-For"); got == "198.51.100.9" || got == "" {
		t.Fatalf("untrusted forwarding address reached target: %q", got)
	}

	healthRequest, err := http.NewRequest(http.MethodGet, "http://"+httpAddr+"/_tunnl/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	healthRequest.Host = "stable-name.tunnl.test"
	healthResponse, err := http.DefaultClient.Do(healthRequest)
	if err != nil {
		t.Fatal(err)
	}
	healthBody, err := io.ReadAll(healthResponse.Body)
	healthResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(healthBody); got != "hello through tunnl: /_tunnl/health" {
		t.Fatalf("tunnel health path was intercepted: %q", got)
	}

	uploadCtx, cancelUpload := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelUpload()
	uploadRequest, err := http.NewRequestWithContext(uploadCtx, http.MethodPost, "http://"+httpAddr+"/reject-upload", bytes.NewReader(make([]byte, 16<<20)))
	if err != nil {
		t.Fatal(err)
	}
	uploadRequest.Host = "stable-name.tunnl.test"
	uploadResponse, err := http.DefaultClient.Do(uploadRequest)
	if err != nil {
		t.Fatalf("early upload response deadlocked: %v", err)
	}
	uploadBody, err := io.ReadAll(uploadResponse.Body)
	uploadResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if uploadResponse.StatusCode != http.StatusRequestEntityTooLarge || string(uploadBody) != "rejected" {
		t.Fatalf("early upload response: status=%d body=%q", uploadResponse.StatusCode, uploadBody)
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

func TestHeartbeatTimeoutDisconnectsClient(t *testing.T) {
	httpAddr := freeTCPAddr(t)
	quicAddr := freeUDPAddr(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := server.New(server.Config{
		HTTPAddr:         httpAddr,
		QUICAddr:         quicAddr,
		BaseDomain:       "tunnl.test",
		Database:         filepath.Join(t.TempDir(), "tunnl.db"),
		AuthTokens:       []string{"integration-secret"},
		HeartbeatTimeout: 200 * time.Millisecond,
		Logger:           logger,
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

	target := targetURL(t, "http://127.0.0.1:3001")
	clientCtx, stopClient := context.WithCancel(context.Background())
	defer stopClient()
	ready := make(chan protocol.Welcome, 1)
	tunnel, err := client.New(client.Config{
		Server:             quicAddr,
		Token:              "integration-secret",
		Domain:             "heartbeat-test",
		Target:             target,
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
	case <-ready:
	case err := <-clientErrors:
		t.Fatalf("client stopped before ready: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("client did not become ready")
	}
	select {
	case err := <-clientErrors:
		if err == nil {
			t.Fatal("heartbeat timeout closed client without a reconnectable error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client remained connected after heartbeat timeout")
	}
	stopServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestManagedTokenConnectsAndRevocationDisconnects(t *testing.T) {
	httpAddr := freeTCPAddr(t)
	quicAddr := freeUDPAddr(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service, err := server.New(server.Config{
		HTTPAddr:   httpAddr,
		QUICAddr:   quicAddr,
		BaseDomain: "tunnl.test",
		Database:   filepath.Join(t.TempDir(), "tunnl.db"),
		AdminAddr:  "127.0.0.1:0",
		AdminToken: strings.Repeat("a", 32),
		Logger:     logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	created, err := service.CreateToken(context.Background(), "integration client")
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- service.Run(serverCtx) }()
	waitForHealth(t, httpAddr)

	clientCtx, stopClient := context.WithCancel(context.Background())
	defer stopClient()
	ready := make(chan protocol.Welcome, 1)
	tunnel, err := client.New(client.Config{
		Server:             quicAddr,
		Token:              created.Secret,
		Domain:             "managed-token",
		Target:             targetURL(t, "http://127.0.0.1:3001"),
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
	case <-ready:
	case err := <-clientErrors:
		t.Fatalf("managed-token client stopped before ready: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("managed-token client did not become ready")
	}
	if err := service.RevokeToken(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-clientErrors:
		if err == nil {
			t.Fatal("revocation stopped client without an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revocation did not disconnect client")
	}
	stopServer()
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatalf("server shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
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
