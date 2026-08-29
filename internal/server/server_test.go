package server

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()
	if !constantTimeEqual("correct horse", "correct horse") {
		t.Fatal("equal tokens were rejected")
	}
	if constantTimeEqual("correct horse", "wrong horse") {
		t.Fatal("different tokens were accepted")
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	t.Parallel()
	headers := http.Header{
		"Connection":         {"keep-alive, X-Private"},
		"Keep-Alive":         {"timeout=5"},
		"Proxy-Authenticate": {"secret"},
		"X-Private":          {"secret"},
		"X-Public":           {"visible"},
	}
	removeHopByHopHeaders(headers)
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "X-Private"} {
		if headers.Get(name) != "" {
			t.Errorf("hop-by-hop header %s was preserved", name)
		}
	}
	if headers.Get("X-Public") != "visible" {
		t.Fatal("end-to-end header was removed")
	}
}

func TestForwardingHeadersRejectSpoofing(t *testing.T) {
	t.Parallel()
	request, err := http.NewRequest(http.MethodGet, "http://demo.tunnl.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.RemoteAddr = "203.0.113.7:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	request.Header.Set("Forwarded", "for=198.51.100.9")
	request.Header.Set("X-Real-IP", "198.51.100.9")
	addForwardingHeaders(request, false)
	if got := request.Header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Fatalf("X-Forwarded-For = %q, want direct peer address", got)
	}
	if request.Header.Get("Forwarded") != "" || request.Header.Get("X-Real-IP") != "" {
		t.Fatal("untrusted forwarding headers were preserved")
	}
}

func TestForwardingHeadersFromTrustedProxy(t *testing.T) {
	t.Parallel()
	request, err := http.NewRequest(http.MethodGet, "http://demo.tunnl.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.RemoteAddr = "203.0.113.7:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	addForwardingHeaders(request, true)
	if got := request.Header.Get("X-Forwarded-For"); got != "198.51.100.9, 203.0.113.7" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
}

func TestAdminListenerDefaultsToLoopback(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		HTTPAddr:   "127.0.0.1:0",
		QUICAddr:   "127.0.0.1:0",
		BaseDomain: "tunnl.test",
		Database:   filepath.Join(t.TempDir(), "tunnl.db"),
		AdminAddr:  ":9090",
		AdminToken: strings.Repeat("a", 32),
	})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("remote admin listener error = %v", err)
	}
}

func TestManagedClientTokenAuthenticationAndRevocation(t *testing.T) {
	t.Parallel()
	service, err := New(Config{
		HTTPAddr:   "127.0.0.1:0",
		QUICAddr:   "127.0.0.1:0",
		BaseDomain: "tunnl.test",
		Database:   filepath.Join(t.TempDir(), "tunnl.db"),
		AdminAddr:  "127.0.0.1:9090",
		AdminToken: strings.Repeat("a", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	ctx := context.Background()
	created, err := service.CreateToken(ctx, "test client")
	if err != nil {
		t.Fatal(err)
	}
	if !service.authenticate(ctx, created.Secret) {
		t.Fatal("managed client token was rejected")
	}
	if err := service.RevokeToken(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if service.authenticate(ctx, created.Secret) {
		t.Fatal("revoked managed client token was accepted")
	}
}
