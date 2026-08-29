package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type Backend interface {
	Status(context.Context) (Status, error)
	Metrics(context.Context) (Metrics, error)
	Tokens(context.Context) ([]Token, error)
	CreateToken(context.Context, string) (CreatedToken, error)
	RevokeToken(context.Context, string) error
	DNS(context.Context) (DNSConfig, error)
	SetDNS(context.Context, DNSConfig) (DNSConfig, error)
	ReconcileDNS(context.Context) (OperationResult, error)
}

type session struct {
	csrf      string
	expiresAt time.Time
}

type Handler struct {
	adminToken string
	backend    Backend
	logger     *slog.Logger
	index      *template.Template
	login      *template.Template
	mu         sync.Mutex
	sessions   map[string]session
}

func NewHandler(adminToken string, backend Backend, logger *slog.Logger) (*Handler, error) {
	if len(adminToken) < 32 {
		return nil, errors.New("admin token must contain at least 32 characters")
	}
	if backend == nil {
		return nil, errors.New("admin backend is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	index, err := template.ParseFS(webFiles, "web/index.html")
	if err != nil {
		return nil, err
	}
	login, err := template.ParseFS(webFiles, "web/login.html")
	if err != nil {
		return nil, err
	}
	return &Handler{adminToken: adminToken, backend: backend, logger: logger, index: index, login: login, sessions: make(map[string]session)}, nil
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", h.loginPage)
	mux.HandleFunc("POST /login", h.loginSubmit)
	mux.HandleFunc("POST /logout", h.requireAuth(h.logout))
	mux.HandleFunc("GET /assets/app.css", h.asset("web/app.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /assets/app.js", h.asset("web/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /", h.requireAuth(h.indexPage))
	mux.HandleFunc("GET /api/v1/status", h.requireAuth(h.status))
	mux.HandleFunc("GET /api/v1/metrics", h.requireAuth(h.metrics))
	mux.HandleFunc("GET /api/v1/tokens", h.requireAuth(h.tokens))
	mux.HandleFunc("POST /api/v1/tokens", h.requireAuth(h.createToken))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", h.requireAuth(h.revokeToken))
	mux.HandleFunc("GET /api/v1/dns", h.requireAuth(h.dns))
	mux.HandleFunc("PUT /api/v1/dns", h.requireAuth(h.setDNS))
	mux.HandleFunc("POST /api/v1/dns/reconcile", h.requireAuth(h.reconcileDNS))
	return h.securityHeaders(mux)
}

func (h *Handler) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		kind, csrf, ok := h.authorize(request)
		if !ok {
			if strings.HasPrefix(request.URL.Path, "/api/") {
				writeError(writer, http.StatusUnauthorized, "authentication required")
				return
			}
			http.Redirect(writer, request, "/login", http.StatusSeeOther)
			return
		}
		if kind == "session" && request.Method != http.MethodGet && request.Method != http.MethodHead && !constantTimeEqual(request.Header.Get("X-CSRF-Token"), csrf) {
			writeError(writer, http.StatusForbidden, "invalid CSRF token")
			return
		}
		next(writer, request)
	}
}

func (h *Handler) authorize(request *http.Request) (kind, csrf string, ok bool) {
	if authorization := request.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
		if constantTimeEqual(strings.TrimPrefix(authorization, "Bearer "), h.adminToken) {
			return "bearer", "", true
		}
		return "", "", false
	}
	cookie, err := request.Cookie("tunnl_admin_session")
	if err != nil {
		return "", "", false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	value, exists := h.sessions[cookie.Value]
	if !exists || time.Now().After(value.expiresAt) {
		delete(h.sessions, cookie.Value)
		return "", "", false
	}
	return "session", value.csrf, true
}

func (h *Handler) loginPage(writer http.ResponseWriter, request *http.Request) {
	if _, _, ok := h.authorize(request); ok {
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.login.Execute(writer, struct{ Error bool }{Error: request.URL.Query().Get("error") != ""})
}

func (h *Handler) loginSubmit(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, 8<<10)
	if err := request.ParseForm(); err != nil || !constantTimeEqual(request.FormValue("token"), h.adminToken) {
		time.Sleep(250 * time.Millisecond)
		http.Redirect(writer, request, "/login?error=1", http.StatusSeeOther)
		return
	}
	id, err := randomValue(32)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "could not create session")
		return
	}
	csrf, err := randomValue(24)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "could not create session")
		return
	}
	h.mu.Lock()
	h.sessions[id] = session{csrf: csrf, expiresAt: time.Now().Add(12 * time.Hour)}
	h.mu.Unlock()
	secureCookie := request.TLS != nil || strings.EqualFold(request.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(writer, &http.Cookie{Name: "tunnl_admin_session", Value: id, Path: "/", HttpOnly: true, Secure: secureCookie, SameSite: http.SameSiteStrictMode, MaxAge: 12 * 60 * 60})
	http.Redirect(writer, request, "/", http.StatusSeeOther)
}

func (h *Handler) logout(writer http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie("tunnl_admin_session"); err == nil {
		h.mu.Lock()
		delete(h.sessions, cookie.Value)
		h.mu.Unlock()
	}
	http.SetCookie(writer, &http.Cookie{Name: "tunnl_admin_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writer.WriteHeader(http.StatusNoContent)
}

func (h *Handler) indexPage(writer http.ResponseWriter, request *http.Request) {
	_, csrf, _ := h.authorize(request)
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.index.Execute(writer, struct{ CSRF string }{CSRF: csrf}); err != nil {
		h.logger.Error("render admin page", "error", err)
	}
}

func (h *Handler) asset(name, contentType string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		data, err := webFiles.ReadFile(name)
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", contentType)
		writer.Write(data)
	}
}

func (h *Handler) status(writer http.ResponseWriter, request *http.Request) {
	result, err := h.backend.Status(request.Context())
	writeResult(writer, result, err)
}

func (h *Handler) metrics(writer http.ResponseWriter, request *http.Request) {
	result, err := h.backend.Metrics(request.Context())
	writeResult(writer, result, err)
}

func (h *Handler) tokens(writer http.ResponseWriter, request *http.Request) {
	result, err := h.backend.Tokens(request.Context())
	writeResult(writer, result, err)
}

func (h *Handler) createToken(writer http.ResponseWriter, request *http.Request) {
	var body CreateTokenRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.backend.CreateToken(request.Context(), body.Label)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusCreated, result)
}

func (h *Handler) revokeToken(writer http.ResponseWriter, request *http.Request) {
	if err := h.backend.RevokeToken(request.Context(), request.PathValue("id")); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (h *Handler) dns(writer http.ResponseWriter, request *http.Request) {
	result, err := h.backend.DNS(request.Context())
	writeResult(writer, result, err)
}

func (h *Handler) setDNS(writer http.ResponseWriter, request *http.Request) {
	var body DNSConfig
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.backend.SetDNS(request.Context(), body)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func (h *Handler) reconcileDNS(writer http.ResponseWriter, request *http.Request) {
	result, err := h.backend.ReconcileDNS(request.Context())
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func writeResult(writer http.ResponseWriter, value any, err error) {
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "operation failed")
		return
	}
	writeJSON(writer, http.StatusOK, value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func constantTimeEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func GenerateAdminToken() (string, error) {
	value, err := randomValue(32)
	if err != nil {
		return "", err
	}
	return "tna_" + value, nil
}
