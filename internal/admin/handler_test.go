package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testAdminToken = "this-is-a-long-test-admin-token-1234567890"

type fakeBackend struct{}

func (fakeBackend) Status(context.Context) (Status, error)  { return Status{Version: "0.1.0"}, nil }
func (fakeBackend) Tokens(context.Context) ([]Token, error) { return []Token{}, nil }
func (fakeBackend) CreateToken(_ context.Context, label string) (CreatedToken, error) {
	return CreatedToken{Token: Token{ID: "one", Label: label}, Secret: "tnl_secret"}, nil
}
func (fakeBackend) RevokeToken(context.Context, string) error { return nil }
func (fakeBackend) DNS(context.Context) (DNSConfig, error) {
	return DNSConfig{Provider: "manual"}, nil
}
func (fakeBackend) SetDNS(_ context.Context, value DNSConfig) (DNSConfig, error) { return value, nil }
func (fakeBackend) ReconcileDNS(context.Context) (OperationResult, error) {
	return OperationResult{Message: "done"}, nil
}

func TestHandlerRequiresStrongAdminToken(t *testing.T) {
	t.Parallel()
	if _, err := NewHandler("short", fakeBackend{}, nil); err == nil {
		t.Fatal("short admin token was accepted")
	}
}

func TestHandlerBearerAuthentication(t *testing.T) {
	t.Parallel()
	handler, err := NewHandler(testAdminToken, fakeBackend{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("unauthorized response = %d, headers=%v", response.Code, response.Header())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	request.Header.Set("Authorization", "Bearer "+testAdminToken)
	response = httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated response = %d: %s", response.Code, response.Body.String())
	}
	var status Status
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil || status.Version != "0.1.0" {
		t.Fatalf("status = %#v, %v", status, err)
	}
}

func TestHandlerBrowserSessionRequiresCSRF(t *testing.T) {
	t.Parallel()
	handler, err := NewHandler(testAdminToken, fakeBackend{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"token": {testAdminToken}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || len(response.Result().Cookies()) != 1 {
		t.Fatalf("login response = %d, cookies=%v", response.Code, response.Result().Cookies())
	}
	cookie := response.Result().Cookies()[0]

	request = httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(`{"label":"Andy"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF = %d", response.Code)
	}

	handler.mu.Lock()
	csrf := handler.sessions[cookie.Value].csrf
	handler.mu.Unlock()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/tokens", strings.NewReader(`{"label":"Andy"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(cookie)
	response = httptest.NewRecorder()
	handler.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("mutation with CSRF = %d: %s", response.Code, response.Body.String())
	}
}
