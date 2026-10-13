package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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
	config, _, showVersion, err := loadServerConfig(os.Args[1:], os.Stderr)
	if err != nil {
		return err
	}
	if showVersion {
		fmt.Printf("tunnld %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return nil
	}
	service, err := server.New(config)
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
	url := envOr("TUNNL_HEALTH_URL", "http://127.0.0.1:8080/_tunnl/ready")
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
