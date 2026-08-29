package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
)

func TestNewSourceGeneratesDevelopmentWildcard(t *testing.T) {
	t.Parallel()
	source, err := NewSource(context.Background(), Options{BaseDomain: "tunnl.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if !source.Generated() || source.Managed() {
		t.Fatalf("generated = %v, managed = %v", source.Generated(), source.Managed())
	}
	config := source.TLSConfig(tls.VersionTLS13, "tunnl/1")
	if config.MinVersion != tls.VersionTLS13 || len(config.Certificates) != 1 {
		t.Fatal("development certificate was not installed in TLS config")
	}
	certificate, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := certificate.VerifyHostname("demo.tunnl.test"); err != nil {
		t.Fatalf("development wildcard does not cover tunnel hostname: %v", err)
	}
	status := source.Status()
	if status.Mode != "development" || status.State != "valid" || status.NotAfter.IsZero() || status.RenewalWindowStart.IsZero() {
		t.Fatalf("unexpected certificate status: %#v", status)
	}
}

func TestSourceTracksCertificateEvents(t *testing.T) {
	t.Parallel()
	source := &Source{}
	if err := source.onEvent(context.Background(), "cert_failed", map[string]any{"error": "challenge failed"}); err != nil {
		t.Fatal(err)
	}
	status := source.Status()
	if status.LastEvent != "cert_failed" || status.LastError != "challenge failed" {
		t.Fatalf("event status = %#v", status)
	}
	if err := source.onEvent(context.Background(), "cert_obtained", nil); err != nil {
		t.Fatal(err)
	}
	status = source.Status()
	if status.LastEvent != "cert_obtained" || status.LastError != "" {
		t.Fatalf("recovery status = %#v", status)
	}
}

func TestNewSourceRejectsIncompleteManualCertificate(t *testing.T) {
	t.Parallel()
	_, err := NewSource(context.Background(), Options{BaseDomain: "tunnl.test", CertPath: "certificate.pem"})
	if err == nil || !strings.Contains(err.Error(), "both TLS certificate and key") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewSourceValidatesACMEBeforeNetworkAccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		options Options
		want    string
	}{
		{
			name:    "manual certificate conflict",
			options: Options{ACMEEnabled: true, CertPath: "certificate.pem"},
			want:    "mutually exclusive",
		},
		{
			name:    "missing email",
			options: Options{ACMEEnabled: true, BaseDomain: "tunnl.test"},
			want:    "email is required",
		},
		{
			name:    "missing storage",
			options: Options{ACMEEnabled: true, BaseDomain: "tunnl.test", ACMEEmail: "operator@example.com"},
			want:    "storage path is required",
		},
		{
			name:    "missing Cloudflare token",
			options: Options{ACMEEnabled: true, BaseDomain: "tunnl.test", ACMEEmail: "operator@example.com", ACMEStorage: t.TempDir()},
			want:    "Cloudflare API token is required",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewSource(context.Background(), test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}
