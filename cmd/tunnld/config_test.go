package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigPrecedence(t *testing.T) {
	t.Setenv("TUNNL_BASE_DOMAIN", "from-env.example")
	t.Setenv("TUNNL_HTTP_ADDR", "127.0.0.1:18080")
	t.Setenv("TUNNL_AUTH_TOKENS", "env-token")
	t.Setenv("TUNNL_AUTH_TOKEN", "")
	t.Setenv("TUNNL_DATABASE", "")
	t.Setenv("TUNNL_REQUEST_TIMEOUT", "")
	t.Setenv("TUNNL_METRICS_ADDR", "")
	t.Setenv("TUNNL_LOG_LEVEL", "")
	directory := t.TempDir()
	path := filepath.Join(directory, "tunnld.json")
	contents := []byte(`{
		"base_domain": "from-file.example",
		"database": "` + filepath.ToSlash(filepath.Join(directory, "tunnl.db")) + `",
		"auth_tokens": "file-token",
		"metrics_addr": "",
		"request_timeout": "45s",
		"log_level": "debug"
	}`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	config, _, showVersion, err := loadServerConfig([]string{
		"--config", path,
		"--base-domain", "from-flag.example",
		"--https-addr", "",
		"--quic-addr", "127.0.0.1:18443",
	}, os.Stderr)
	if err != nil || showVersion {
		t.Fatalf("load config: version=%v err=%v", showVersion, err)
	}
	if config.BaseDomain != "from-flag.example" {
		t.Fatalf("base domain = %q, want the flag", config.BaseDomain)
	}
	if config.HTTPAddr != "127.0.0.1:18080" {
		t.Fatalf("http address = %q, want the environment", config.HTTPAddr)
	}
	if config.Database != filepath.ToSlash(filepath.Join(directory, "tunnl.db")) && config.Database != filepath.Join(directory, "tunnl.db") {
		t.Fatalf("database = %q, want the file", config.Database)
	}
	if len(config.AuthTokens) != 1 || config.AuthTokens[0] != "env-token" {
		t.Fatalf("tokens = %#v, want the environment", config.AuthTokens)
	}
	if config.MetricsAddr != "" {
		t.Fatalf("metrics address = %q, want disabled by the file", config.MetricsAddr)
	}
	if config.RequestTimeout != 45*time.Second {
		t.Fatalf("request timeout = %s, want the file", config.RequestTimeout)
	}
	if config.HTTPSAddr != "" || config.QUICAddr != "127.0.0.1:18443" {
		t.Fatalf("listeners https=%q quic=%q", config.HTTPSAddr, config.QUICAddr)
	}
}

func TestConfigRejectsUnknownFileFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tunnld.json")
	if err := os.WriteFile(path, []byte(`{"not_a_field": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := loadServerConfig([]string{"--config", path, "--auth-tokens", "token"}, os.Stderr); err == nil {
		t.Fatal("unknown config field was accepted")
	}
}

func TestConfigAllowsAdminWithoutBootstrapToken(t *testing.T) {
	config, _, _, err := loadServerConfig([]string{
		"--admin-addr", "127.0.0.1:9090",
		"--admin-token", "this-is-a-long-test-admin-token-1234567890",
		"--metrics-addr", "",
	}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.AuthTokens) != 0 || config.AdminAddr != "127.0.0.1:9090" {
		t.Fatalf("config = %+v", config)
	}
}
