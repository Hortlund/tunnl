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

		var config *certmagic.Config
		cache := certmagic.NewCache(certmagic.CacheOptions{
			GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
				return config, nil
			},
		})
		config = certmagic.New(cache, certmagic.Config{
			Storage: &certmagic.FileStorage{Path: options.ACMEStorage},
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
		return &Source{magic: config, cache: cache}, nil
	}

	certificate, generated, err := LoadOrGenerate(options.CertPath, options.KeyPath, options.BaseDomain)
	if err != nil {
		return nil, err
	}
	return &Source{certificate: &certificate, generated: generated}, nil
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
