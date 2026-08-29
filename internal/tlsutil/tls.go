package tlsutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	cloudflaredns "github.com/libdns/cloudflare"
)

type Options struct {
	CertPath           string
	KeyPath            string
	BaseDomain         string
	ACMEEnabled        bool
	ACMEEmail          string
	ACMEStorage        string
	ACMEStaging        bool
	CloudflareAPIToken string
}

type Source struct {
	certificate *tls.Certificate
	magic       *certmagic.Config
	cache       *certmagic.Cache
	generated   bool
	mode        string
	baseDomain  string
	staging     bool
	mu          sync.RWMutex
	lastEvent   string
	lastEventAt time.Time
	lastError   string
}

type Status struct {
	Mode               string
	State              string
	Provider           string
	Staging            bool
	Names              []string
	Issuer             string
	Serial             string
	NotBefore          time.Time
	NotAfter           time.Time
	RenewalWindowStart time.Time
	LastEvent          string
	LastEventAt        time.Time
	LastError          string
}

func NewSource(ctx context.Context, options Options) (*Source, error) {
	if options.ACMEEnabled {
		if options.CertPath != "" || options.KeyPath != "" {
			return nil, fmt.Errorf("automatic ACME and manual TLS certificate files are mutually exclusive")
		}
		if options.BaseDomain == "" {
			return nil, fmt.Errorf("base domain is required for automatic ACME")
		}
		if options.ACMEEmail == "" {
			return nil, fmt.Errorf("ACME account email is required")
		}
		if options.ACMEStorage == "" {
			return nil, fmt.Errorf("ACME storage path is required")
		}
		if options.CloudflareAPIToken == "" {
			return nil, fmt.Errorf("Cloudflare API token is required for ACME DNS-01")
		}
		if err := os.MkdirAll(options.ACMEStorage, 0o700); err != nil {
			return nil, fmt.Errorf("create ACME storage: %w", err)
		}

		source := &Source{mode: "acme", baseDomain: options.BaseDomain, staging: options.ACMEStaging}
		var config *certmagic.Config
		cache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
				return config, nil
			},
		})
		config = certmagic.New(cache, certmagic.Config{
			Storage: &certmagic.FileStorage{Path: options.ACMEStorage},
			OnEvent: source.onEvent,
		})
		ca := certmagic.LetsEncryptProductionCA
		if options.ACMEStaging {
			ca = certmagic.LetsEncryptStagingCA
		}
		config.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(config, certmagic.ACMEIssuer{
			CA:                      ca,
			Email:                   options.ACMEEmail,
			Agreed:                  true,
			DisableHTTPChallenge:    true,
			DisableTLSALPNChallenge: true,
			DNS01Solver: &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
				DNSProvider: &cloudflaredns.Provider{APIToken: options.CloudflareAPIToken},
			}},
		})}
		if err := config.ManageSync(ctx, []string{"*." + options.BaseDomain}); err != nil {
			cache.Stop()
			return nil, fmt.Errorf("obtain wildcard certificate: %w", err)
		}
		source.magic = config
		source.cache = cache
		return source, nil
	}

	certificate, generated, err := LoadOrGenerate(options.CertPath, options.KeyPath, options.BaseDomain)
	if err != nil {
		return nil, err
	}
	mode := "manual"
	if generated {
		mode = "development"
	}
	return &Source{certificate: &certificate, generated: generated, mode: mode, baseDomain: options.BaseDomain}, nil
}

func (s *Source) TLSConfig(minVersion uint16, nextProtos ...string) *tls.Config {
	config := &tls.Config{MinVersion: minVersion, NextProtos: append([]string(nil), nextProtos...)}
	if s.magic != nil {
		config.GetCertificate = s.magic.GetCertificate
	} else {
		config.Certificates = []tls.Certificate{*s.certificate}
	}
	return config
}

func (s *Source) Generated() bool { return s.generated }

func (s *Source) Managed() bool { return s.magic != nil }

func (s *Source) Status() Status {
	status := Status{Mode: s.mode, Staging: s.staging}
	if s.magic != nil {
		status.Provider = "Let's Encrypt"
	}
	s.mu.RLock()
	status.LastEvent = s.lastEvent
	status.LastEventAt = s.lastEventAt
	status.LastError = s.lastError
	s.mu.RUnlock()

	certificate := s.certificate
	if s.magic != nil {
		managed, err := s.magic.GetCertificate(&tls.ClientHelloInfo{ServerName: "relay." + s.baseDomain})
		if err != nil {
			status.State = "unavailable"
			if status.LastError == "" {
				status.LastError = err.Error()
			}
			return status
		}
		certificate = managed
	}
	if certificate == nil || len(certificate.Certificate) == 0 {
		status.State = "unavailable"
		return status
	}
	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			status.State = "unavailable"
			status.LastError = err.Error()
			return status
		}
	}
	status.Names = append([]string(nil), leaf.DNSNames...)
	status.Issuer = leaf.Issuer.CommonName
	status.Serial = leaf.SerialNumber.Text(16)
	status.NotBefore = leaf.NotBefore.UTC()
	status.NotAfter = leaf.NotAfter.UTC()
	status.RenewalWindowStart = leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3).UTC()
	now := time.Now()
	switch {
	case status.LastEvent == "cert_ocsp_revoked":
		status.State = "revoked"
	case status.LastEvent == "cert_obtaining":
		status.State = "renewing"
	case status.LastEvent == "cert_failed" && time.Since(status.LastEventAt) < 24*time.Hour:
		status.State = "error"
	case !now.Before(leaf.NotAfter):
		status.State = "expired"
	case !now.Before(status.RenewalWindowStart):
		status.State = "renewal_due"
	default:
		status.State = "valid"
	}
	return status
}

func (s *Source) onEvent(_ context.Context, event string, data map[string]any) error {
	switch event {
	case "cert_obtaining", "cert_obtained", "cert_failed", "cert_ocsp_revoked", "cached_managed_cert":
	default:
		return nil
	}
	s.mu.Lock()
	s.lastEvent = event
	s.lastEventAt = time.Now().UTC()
	if event == "cert_failed" {
		s.lastError = fmt.Sprint(data["error"])
	} else if event == "cert_obtained" || event == "cached_managed_cert" {
		s.lastError = ""
	}
	s.mu.Unlock()
	return nil
}

func (s *Source) Close() {
	if s.cache != nil {
		s.cache.Stop()
	}
}

func LoadOrGenerate(certPath, keyPath, baseDomain string) (tls.Certificate, bool, error) {
	if certPath != "" || keyPath != "" {
		if certPath == "" || keyPath == "" {
			return tls.Certificate{}, false, fmt.Errorf("both TLS certificate and key are required")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		return cert, false, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, true, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, true, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tunnl development certificate"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", baseDomain, "*." + baseDomain},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, true, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, true, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, true, err
}

func ValidateFiles(certPath, keyPath string) error {
	for _, path := range []string{certPath, keyPath} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return err
		}
	}
	return nil
}
