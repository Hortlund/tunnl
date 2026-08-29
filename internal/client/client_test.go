package client

import (
	"net/url"
	"testing"
	"time"
)

func TestJoinURLPath(t *testing.T) {
	t.Parallel()
	tests := []struct{ base, request, want string }{
		{"", "/users", "/users"},
		{"/api", "/users", "/api/users"},
		{"/api/", "/users/", "/api/users/"},
	}
	for _, test := range tests {
		if got := joinURLPath(test.base, test.request); got != test.want {
			t.Errorf("joinURLPath(%q, %q) = %q, want %q", test.base, test.request, got, test.want)
		}
	}
}

func TestResponseHeaderTimeoutConfiguration(t *testing.T) {
	t.Parallel()
	target, err := url.Parse("http://127.0.0.1:3000")
	if err != nil {
		t.Fatal(err)
	}
	withoutTimeout, err := New(Config{Server: "relay.test:443", Token: "secret", Target: target})
	if err != nil {
		t.Fatal(err)
	}
	if withoutTimeout.transport.ResponseHeaderTimeout != 0 {
		t.Fatalf("default timeout = %s, want disabled", withoutTimeout.transport.ResponseHeaderTimeout)
	}
	withTimeout, err := New(Config{Server: "relay.test:443", Token: "secret", Target: target, ResponseHeaderTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if withTimeout.transport.ResponseHeaderTimeout != 2*time.Minute {
		t.Fatalf("configured timeout = %s", withTimeout.transport.ResponseHeaderTimeout)
	}
}
