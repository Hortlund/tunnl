package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hortlund/tunnl/internal/server"
)

const (
	defaultHTTPAddr         = ":8080"
	defaultHTTPSAddr        = ":8443"
	defaultQUICAddr         = ":8443"
	defaultBaseDomain       = "tunnl.at"
	defaultDatabase         = ".data/tunnl.db"
	defaultACMEStorage      = ".data/acme"
	defaultPublicPort       = 8443
	defaultMetricsAddr      = "127.0.0.1:9091"
	defaultMaxBody          = 32 << 20
	defaultAcceptLimit      = 30
	defaultHandshakeLimit   = 20
	defaultLogLevel         = "info"
	defaultHeartbeatTimeout = 40 * time.Second
	defaultRequestTimeout   = 2 * time.Minute
)

type fileConfig struct {
	HTTPAddr              *string `json:"http_addr"`
	HTTPSAddr             *string `json:"https_addr"`
	QUICAddr              *string `json:"quic_addr"`
	BaseDomain            *string `json:"base_domain"`
	Database              *string `json:"database"`
	AuthToken             *string `json:"auth_token"`
	AuthTokens            *string `json:"auth_tokens"`
	TLSCert               *string `json:"tls_cert"`
	TLSKey                *string `json:"tls_key"`
	ACME                  *bool   `json:"acme"`
	ACMEEmail             *string `json:"acme_email"`
	ACMEStorage           *string `json:"acme_storage"`
	ACMEStaging           *bool   `json:"acme_staging"`
	AdminAddr             *string `json:"admin_addr"`
	AdminToken            *string `json:"admin_token"`
	AdminAllowRemote      *bool   `json:"admin_allow_remote"`
	CloudflareAPIToken    *string `json:"cloudflare_api_token"`
	PublicPort            *int    `json:"public_port"`
	TrustProxyHeaders     *bool   `json:"trust_proxy_headers"`
	HeartbeatTimeout      *string `json:"heartbeat_timeout"`
	MetricsAddr           *string `json:"metrics_addr"`
	MaxRequestBody        *int64  `json:"max_request_body"`
	MaxResponseBody       *int64  `json:"max_response_body"`
	RequestTimeout        *string `json:"request_timeout"`
	AcceptLimit           *int    `json:"accept_limit"`
	HandshakeFailureLimit *int    `json:"handshake_failure_limit"`
	LogLevel              *string `json:"log_level"`
}

func loadServerConfig(args []string, output io.Writer) (server.Config, *slog.Logger, bool, error) {
	flags := flag.NewFlagSet("tunnld", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.String("config", "", "JSON config file (or TUNNL_CONFIG)")
	flags.String("http-addr", "", "public HTTP listen address")
	flags.String("https-addr", "", "public HTTPS listen address")
	flags.String("quic-addr", "", "QUIC relay listen address")
	flags.String("base-domain", "", "base domain for public tunnels")
	flags.String("database", "", "SQLite database path")
	flags.String("auth-token", "", "shared authentication token")
	flags.String("auth-tokens", "", "comma-separated client tokens")
	flags.String("tls-cert", "", "TLS certificate path")
	flags.String("tls-key", "", "TLS private key path")
	flags.Bool("acme", false, "automatically manage a Let's Encrypt wildcard certificate with Cloudflare DNS-01")
	flags.String("acme-email", "", "email for the Let's Encrypt ACME account")
	flags.String("acme-storage", "", "persistent directory for ACME account and certificate state")
	flags.Bool("acme-staging", false, "use the untrusted Let's Encrypt staging environment")
	flags.String("admin-addr", "", "optional admin UI/API listen address")
	flags.String("admin-token", "", "admin UI/API authentication token")
	flags.Bool("admin-allow-remote", false, "allow the admin listener to bind beyond loopback")
	flags.String("cloudflare-api-token", "", "Cloudflare DNS API token")
	flags.Int("public-port", 0, "HTTPS port included in generated URLs")
	flags.Bool("trust-proxy-headers", false, "trust forwarding headers from the ingress proxy")
	flags.Duration("heartbeat-timeout", 0, "maximum time between client heartbeats")
	flags.String("metrics-addr", "", "health, readiness, and Prometheus listen address; empty disables it")
	flags.Int64("max-request-body", 0, "maximum proxied request body in bytes")
	flags.Int64("max-response-body", 0, "maximum proxied response body in bytes")
	flags.Duration("request-timeout", 0, "maximum duration of a proxied request")
	flags.Int("accept-limit", 0, "QUIC accepts allowed per remote IP per minute; -1 disables")
	flags.Int("handshake-failure-limit", 0, "failed handshakes allowed per remote IP per minute; -1 disables")
	flags.String("log-level", "", "log level: debug, info, warn, or error")
	showVersion := flags.Bool("version", false, "print version information")
	if err := flags.Parse(args); err != nil {
		return server.Config{}, nil, false, err
	}
	if *showVersion {
		return server.Config{}, nil, true, nil
	}

	path, err := pickString(flags, "config", "TUNNL_CONFIG", nil, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	file, err := loadFileConfig(path)
	if err != nil {
		return server.Config{}, nil, false, err
	}

	resolvedHTTP, err := pickString(flags, "http-addr", "TUNNL_HTTP_ADDR", file.HTTPAddr, defaultHTTPAddr)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedHTTPS, err := pickString(flags, "https-addr", "TUNNL_HTTPS_ADDR", file.HTTPSAddr, defaultHTTPSAddr)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedQUIC, err := pickString(flags, "quic-addr", "TUNNL_QUIC_ADDR", file.QUICAddr, defaultQUICAddr)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedDomain, err := pickString(flags, "base-domain", "TUNNL_BASE_DOMAIN", file.BaseDomain, defaultBaseDomain)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedDatabase, err := pickString(flags, "database", "TUNNL_DATABASE", file.Database, defaultDatabase)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedAuthToken, err := pickString(flags, "auth-token", "TUNNL_AUTH_TOKEN", file.AuthToken, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedAuthTokens, err := pickString(flags, "auth-tokens", "TUNNL_AUTH_TOKENS", file.AuthTokens, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedCert, err := pickString(flags, "tls-cert", "TUNNL_TLS_CERT", file.TLSCert, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedKey, err := pickString(flags, "tls-key", "TUNNL_TLS_KEY", file.TLSKey, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedACME, err := pickBool(flags, "acme", "TUNNL_ACME", file.ACME, false)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedEmail, err := pickString(flags, "acme-email", "TUNNL_ACME_EMAIL", file.ACMEEmail, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedACMEStorage, err := pickString(flags, "acme-storage", "TUNNL_ACME_STORAGE", file.ACMEStorage, defaultACMEStorage)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedStaging, err := pickBool(flags, "acme-staging", "TUNNL_ACME_STAGING", file.ACMEStaging, false)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedAdminAddr, err := pickString(flags, "admin-addr", "TUNNL_ADMIN_ADDR", file.AdminAddr, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedAdminToken, err := pickString(flags, "admin-token", "TUNNL_ADMIN_TOKEN", file.AdminToken, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedAdminRemote, err := pickBool(flags, "admin-allow-remote", "TUNNL_ADMIN_ALLOW_REMOTE", file.AdminAllowRemote, false)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedCloudflare, err := pickString(flags, "cloudflare-api-token", "TUNNL_CLOUDFLARE_API_TOKEN", file.CloudflareAPIToken, "")
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedPort, err := pickInt(flags, "public-port", "TUNNL_PUBLIC_PORT", file.PublicPort, defaultPublicPort)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedTrust, err := pickBool(flags, "trust-proxy-headers", "TUNNL_TRUST_PROXY_HEADERS", file.TrustProxyHeaders, false)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedHeartbeat, err := pickDuration(flags, "heartbeat-timeout", "TUNNL_HEARTBEAT_TIMEOUT", file.HeartbeatTimeout, defaultHeartbeatTimeout)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedMetrics, err := pickString(flags, "metrics-addr", "TUNNL_METRICS_ADDR", file.MetricsAddr, defaultMetricsAddr)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedMaxRequest, err := pickInt64(flags, "max-request-body", "TUNNL_MAX_REQUEST_BODY", file.MaxRequestBody, defaultMaxBody)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedMaxResponse, err := pickInt64(flags, "max-response-body", "TUNNL_MAX_RESPONSE_BODY", file.MaxResponseBody, defaultMaxBody)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedRequestTimeout, err := pickDuration(flags, "request-timeout", "TUNNL_REQUEST_TIMEOUT", file.RequestTimeout, defaultRequestTimeout)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedAccepts, err := pickInt(flags, "accept-limit", "TUNNL_ACCEPT_LIMIT", file.AcceptLimit, defaultAcceptLimit)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedHandshakes, err := pickInt(flags, "handshake-failure-limit", "TUNNL_HANDSHAKE_FAILURE_LIMIT", file.HandshakeFailureLimit, defaultHandshakeLimit)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	resolvedLevel, err := pickString(flags, "log-level", "TUNNL_LOG_LEVEL", file.LogLevel, defaultLogLevel)
	if err != nil {
		return server.Config{}, nil, false, err
	}
	level, err := parseLogLevel(resolvedLevel)
	if err != nil {
		return server.Config{}, nil, false, err
	}

	tokens := splitTokens(resolvedAuthTokens)
	if resolvedAuthToken != "" {
		tokens = append(tokens, resolvedAuthToken)
	}
	if len(tokens) == 0 && resolvedAdminAddr == "" {
		return server.Config{}, nil, false, errors.New("TUNNL_AUTH_TOKENS or --admin-addr is required")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	return server.Config{
		HTTPAddr:              resolvedHTTP,
		HTTPSAddr:             resolvedHTTPS,
		QUICAddr:              resolvedQUIC,
		BaseDomain:            resolvedDomain,
		PublicPort:            resolvedPort,
		Database:              resolvedDatabase,
		AuthTokens:            tokens,
		TrustProxyHeaders:     resolvedTrust,
		HeartbeatTimeout:      resolvedHeartbeat,
		TLSCert:               resolvedCert,
		TLSKey:                resolvedKey,
		ACMEEnabled:           resolvedACME,
		ACMEEmail:             resolvedEmail,
		ACMEStorage:           resolvedACMEStorage,
		ACMEStaging:           resolvedStaging,
		AdminAddr:             resolvedAdminAddr,
		AdminToken:            resolvedAdminToken,
		AdminAllowRemote:      resolvedAdminRemote,
		CloudflareAPIToken:    resolvedCloudflare,
		MetricsAddr:           resolvedMetrics,
		MaxRequestBody:        resolvedMaxRequest,
		MaxResponseBody:       resolvedMaxResponse,
		RequestTimeout:        resolvedRequestTimeout,
		AcceptLimit:           resolvedAccepts,
		HandshakeFailureLimit: resolvedHandshakes,
		Logger:                logger,
	}, logger, false, nil
}

func loadFileConfig(path string) (fileConfig, error) {
	if path == "" {
		return fileConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, fmt.Errorf("read config file: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var file fileConfig
	if err := decoder.Decode(&file); err != nil {
		return fileConfig{}, fmt.Errorf("parse config file: %w", err)
	}
	return file, nil
}

func pickString(flags *flag.FlagSet, name, envKey string, fileValue *string, fallback string) (string, error) {
	if flagVisited(flags, name) {
		return flags.Lookup(name).Value.String(), nil
	}
	if value, ok := lookupEnv(envKey); ok {
		return value, nil
	}
	if fileValue != nil {
		return *fileValue, nil
	}
	return fallback, nil
}

func pickBool(flags *flag.FlagSet, name, envKey string, fileValue *bool, fallback bool) (bool, error) {
	if flagVisited(flags, name) {
		return strconv.ParseBool(flags.Lookup(name).Value.String())
	}
	if value, ok := lookupEnv(envKey); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return false, fmt.Errorf("%s: %w", envKey, err)
		}
		return parsed, nil
	}
	if fileValue != nil {
		return *fileValue, nil
	}
	return fallback, nil
}

func pickInt(flags *flag.FlagSet, name, envKey string, fileValue *int, fallback int) (int, error) {
	if flagVisited(flags, name) {
		return strconv.Atoi(flags.Lookup(name).Value.String())
	}
	if value, ok := lookupEnv(envKey); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", envKey, err)
		}
		return parsed, nil
	}
	if fileValue != nil {
		return *fileValue, nil
	}
	return fallback, nil
}

func pickInt64(flags *flag.FlagSet, name, envKey string, fileValue *int64, fallback int64) (int64, error) {
	if flagVisited(flags, name) {
		return strconv.ParseInt(flags.Lookup(name).Value.String(), 10, 64)
	}
	if value, ok := lookupEnv(envKey); ok {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", envKey, err)
		}
		return parsed, nil
	}
	if fileValue != nil {
		return *fileValue, nil
	}
	return fallback, nil
}

func pickDuration(flags *flag.FlagSet, name, envKey string, fileValue *string, fallback time.Duration) (time.Duration, error) {
	if flagVisited(flags, name) {
		return time.ParseDuration(flags.Lookup(name).Value.String())
	}
	if value, ok := lookupEnv(envKey); ok {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", envKey, err)
		}
		return parsed, nil
	}
	if fileValue != nil {
		parsed, err := time.ParseDuration(*fileValue)
		if err != nil {
			return 0, fmt.Errorf("config %s: %w", name, err)
		}
		return parsed, nil
	}
	return fallback, nil
}

func flagVisited(flags *flag.FlagSet, name string) bool {
	visited := false
	flags.Visit(func(flag *flag.Flag) {
		if flag.Name == name {
			visited = true
		}
	})
	return visited
}

func lookupEnv(key string) (string, bool) {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", value)
	}
}
