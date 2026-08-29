package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hortlund/tunnl/internal/admin"
	"github.com/Hortlund/tunnl/internal/server"
	"github.com/Hortlund/tunnl/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tunnld:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		return healthcheck()
	}
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		return runAdmin(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "generate-admin-token" {
		token, err := admin.GenerateAdminToken()
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	}
	flags := flag.NewFlagSet("tunnld", flag.ContinueOnError)
	httpAddr := flags.String("http-addr", envOr("TUNNL_HTTP_ADDR", ":8080"), "public HTTP listen address")
	httpsAddr := flags.String("https-addr", envOr("TUNNL_HTTPS_ADDR", ":8443"), "public HTTPS listen address")
	quicAddr := flags.String("quic-addr", envOr("TUNNL_QUIC_ADDR", ":8443"), "QUIC relay listen address")
	baseDomain := flags.String("base-domain", envOr("TUNNL_BASE_DOMAIN", "tunnl.at"), "base domain for public tunnels")
	database := flags.String("database", envOr("TUNNL_DATABASE", ".data/tunnl.db"), "SQLite database path")
	authToken := flags.String("auth-token", os.Getenv("TUNNL_AUTH_TOKEN"), "shared authentication token (or TUNNL_AUTH_TOKEN)")
	authTokens := flags.String("auth-tokens", os.Getenv("TUNNL_AUTH_TOKENS"), "comma-separated client tokens (or TUNNL_AUTH_TOKENS)")
	tlsCert := flags.String("tls-cert", os.Getenv("TUNNL_TLS_CERT"), "TLS certificate path")
	tlsKey := flags.String("tls-key", os.Getenv("TUNNL_TLS_KEY"), "TLS private key path")
	acmeEnabled := flags.Bool("acme", envBool("TUNNL_ACME", false), "automatically manage a Let's Encrypt wildcard certificate with Cloudflare DNS-01")
	acmeEmail := flags.String("acme-email", os.Getenv("TUNNL_ACME_EMAIL"), "email for the Let's Encrypt ACME account")
	acmeStorage := flags.String("acme-storage", envOr("TUNNL_ACME_STORAGE", ".data/acme"), "persistent directory for ACME account and certificate state")
	acmeStaging := flags.Bool("acme-staging", envBool("TUNNL_ACME_STAGING", false), "use the untrusted Let's Encrypt staging environment")
	adminAddr := flags.String("admin-addr", os.Getenv("TUNNL_ADMIN_ADDR"), "optional admin UI/API listen address")
	adminToken := flags.String("admin-token", os.Getenv("TUNNL_ADMIN_TOKEN"), "admin UI/API authentication token")
	adminAllowRemote := flags.Bool("admin-allow-remote", envBool("TUNNL_ADMIN_ALLOW_REMOTE", false), "allow the admin listener to bind beyond loopback")
	cloudflareAPIToken := flags.String("cloudflare-api-token", os.Getenv("TUNNL_CLOUDFLARE_API_TOKEN"), "Cloudflare DNS API token")
	publicPort := flags.Int("public-port", envInt("TUNNL_PUBLIC_PORT", 8443), "HTTPS port included in generated URLs")
	trustProxyHeaders := flags.Bool("trust-proxy-headers", envBool("TUNNL_TRUST_PROXY_HEADERS", false), "trust forwarding headers from the ingress proxy")
	heartbeatTimeout := flags.Duration("heartbeat-timeout", envDuration("TUNNL_HEARTBEAT_TIMEOUT", 40*time.Second), "maximum time between client heartbeats")
	showVersion := flags.Bool("version", false, "print version information")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("tunnld %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return nil
	}
	tokens := splitTokens(*authTokens)
	if *authToken != "" {
		tokens = append(tokens, *authToken)
	}
	if len(tokens) == 0 {
		return errors.New("TUNNL_AUTH_TOKENS or --auth-tokens is required")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	service, err := server.New(server.Config{
		HTTPAddr:           *httpAddr,
		HTTPSAddr:          *httpsAddr,
		QUICAddr:           *quicAddr,
		BaseDomain:         *baseDomain,
		PublicPort:         *publicPort,
		Database:           *database,
		AuthTokens:         tokens,
		TrustProxyHeaders:  *trustProxyHeaders,
		HeartbeatTimeout:   *heartbeatTimeout,
		TLSCert:            *tlsCert,
		TLSKey:             *tlsKey,
		ACMEEnabled:        *acmeEnabled,
		ACMEEmail:          *acmeEmail,
		ACMEStorage:        *acmeStorage,
		ACMEStaging:        *acmeStaging,
		AdminAddr:          *adminAddr,
		AdminToken:         *adminToken,
		AdminAllowRemote:   *adminAllowRemote,
		CloudflareAPIToken: *cloudflareAPIToken,
		Logger:             logger,
	})
	if err != nil {
		return err
	}
	defer service.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return service.Run(ctx)
}

func splitTokens(value string) []string {
	var tokens []string
	for _, token := range strings.Split(value, ",") {
		if token = strings.TrimSpace(token); token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func healthcheck() error {
	url := envOr("TUNNL_HEALTH_URL", "http://127.0.0.1:8080/_tunnl/health")
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
