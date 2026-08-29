package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/Hortlund/tunnl/internal/admin"
	dnsprovider "github.com/Hortlund/tunnl/internal/dns"
	"github.com/Hortlund/tunnl/internal/store"
	"github.com/Hortlund/tunnl/internal/version"
)

func (s *Server) Status(ctx context.Context) (admin.Status, error) {
	reservations, err := s.store.CountReservations(ctx)
	if err != nil {
		return admin.Status{}, err
	}
	managedTokens, err := s.store.CountClientTokens(ctx)
	if err != nil {
		return admin.Status{}, err
	}
	sessions := s.registry.snapshot()
	tunnels := make([]admin.Tunnel, 0, len(sessions))
	for _, value := range sessions {
		tunnels = append(tunnels, admin.Tunnel{Domain: value.domain, Remote: value.remote, ConnectedAt: value.connectedAt})
	}
	return admin.Status{
		Version:          version.Version,
		StartedAt:        s.metrics.startedAt,
		UptimeSeconds:    int64(time.Since(s.metrics.startedAt).Seconds()),
		BaseDomain:       s.config.BaseDomain,
		ActiveTunnels:    len(sessions),
		Reservations:     reservations,
		ManagedTokens:    managedTokens,
		BootstrapTokens:  len(s.config.AuthTokens),
		TotalConnections: s.metrics.totalConnections.Load(),
		TotalRequests:    s.metrics.totalRequests.Load(),
		FailedRequests:   s.metrics.failedRequests.Load(),
		ResponseBytes:    s.metrics.responseBytes.Load(),
		Tunnels:          tunnels,
	}, nil
}

func (s *Server) Tokens(ctx context.Context) ([]admin.Token, error) {
	values, err := s.store.ListClientTokens(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]admin.Token, 0, len(values))
	for _, value := range values {
		result = append(result, admin.Token{ID: value.ID, Label: value.Label, Prefix: value.Prefix, CreatedAt: value.CreatedAt, LastUsedAt: value.LastUsedAt})
	}
	return result, nil
}

func (s *Server) CreateToken(ctx context.Context, label string) (admin.CreatedToken, error) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 80 || strings.IndexFunc(label, unicode.IsControl) >= 0 {
		return admin.CreatedToken{}, errors.New("token label must contain 1 to 80 printable characters")
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return admin.CreatedToken{}, err
	}
	secret := "tnl_" + base64.RawURLEncoding.EncodeToString(random)
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return admin.CreatedToken{}, err
	}
	id := hex.EncodeToString(idBytes)
	prefix := secret[:12]
	if err := s.store.CreateClientToken(ctx, id, label, hashToken(secret), prefix); err != nil {
		return admin.CreatedToken{}, err
	}
	now := time.Now().UTC()
	return admin.CreatedToken{Token: admin.Token{ID: id, Label: label, Prefix: prefix, CreatedAt: now}, Secret: secret}, nil
}

func (s *Server) RevokeToken(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("token ID is required")
	}
	tokenHash, err := s.store.ClientTokenHash(ctx, id)
	if err != nil {
		return errors.New("token was not found")
	}
	deleted, err := s.store.DeleteClientToken(ctx, id)
	if err != nil {
		return err
	}
	if !deleted {
		return errors.New("token was not found")
	}
	disconnected := s.registry.disconnectToken(tokenHash)
	s.logger.Info("client token revoked", "token_id", id, "disconnected_tunnels", disconnected)
	return nil
}

func (s *Server) DNS(ctx context.Context) (admin.DNSConfig, error) {
	value, err := s.store.DNSConfig(ctx)
	if err != nil {
		return admin.DNSConfig{}, err
	}
	return admin.DNSConfig{Provider: value.Provider, Zone: value.Zone, Target: value.Target, UpdatedAt: value.UpdatedAt, CredentialAvailable: s.config.CloudflareAPIToken != ""}, nil
}

func (s *Server) SetDNS(ctx context.Context, config admin.DNSConfig) (admin.DNSConfig, error) {
	config.Provider = strings.ToLower(strings.TrimSpace(config.Provider))
	config.Zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(config.Zone)), ".")
	config.Target = strings.TrimSpace(config.Target)
	switch config.Provider {
	case "manual":
	case "cloudflare":
		baseDomain := strings.TrimSuffix(strings.ToLower(s.config.BaseDomain), ".")
		if config.Zone == "" || (baseDomain != config.Zone && !strings.HasSuffix(baseDomain, "."+config.Zone)) {
			return admin.DNSConfig{}, errors.New("DNS zone must contain the configured base domain")
		}
		if net.ParseIP(config.Target) == nil {
			return admin.DNSConfig{}, errors.New("Cloudflare requires a valid server IPv4 or IPv6 target")
		}
	default:
		return admin.DNSConfig{}, errors.New("DNS provider must be manual or cloudflare")
	}
	if err := s.store.SetDNSConfig(ctx, store.DNSConfig{Provider: config.Provider, Zone: config.Zone, Target: config.Target}); err != nil {
		return admin.DNSConfig{}, err
	}
	return s.DNS(ctx)
}

func (s *Server) ReconcileDNS(ctx context.Context) (admin.OperationResult, error) {
	config, err := s.DNS(ctx)
	if err != nil {
		return admin.OperationResult{}, err
	}
	if config.Provider != "cloudflare" {
		return admin.OperationResult{}, errors.New("Cloudflare must be selected before reconciling DNS")
	}
	cloudflare := dnsprovider.NewCloudflare(s.config.CloudflareAPIToken)
	if err := cloudflare.Reconcile(ctx, config.Zone, s.config.BaseDomain, config.Target); err != nil {
		return admin.OperationResult{}, fmt.Errorf("reconcile Cloudflare DNS: %w", err)
	}
	s.logger.Info("Cloudflare DNS reconciled", "zone", config.Zone, "target", config.Target)
	return admin.OperationResult{Message: "Cloudflare DNS records reconciled"}, nil
}
