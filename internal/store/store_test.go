package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestReservationOwnershipPersists(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "tunnl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	owner := tokenHash("owner")
	if err := database.Reserve(ctx, "geph", owner); err != nil {
		t.Fatal(err)
	}
	if err := database.Reserve(ctx, "geph", owner); err != nil {
		t.Fatalf("same owner could not reclaim domain: %v", err)
	}
	if err := database.Reserve(ctx, "geph", tokenHash("stranger")); !errors.Is(err, ErrDomainTaken) {
		t.Fatalf("different owner error = %v, want ErrDomainTaken", err)
	}
	got, err := database.Owner(ctx, "geph")
	if err != nil || got != owner {
		t.Fatalf("Owner() = %q, %v; want %q", got, err, owner)
	}
}

func TestClientTokenLifecycle(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "tunnl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	hash := tokenHash("tnl_secret")
	if err := database.CreateClientToken(ctx, "token-id", "Andy", hash, "tnl_secret"); err != nil {
		t.Fatal(err)
	}
	matched, err := database.AuthenticateClientToken(ctx, hash)
	if err != nil || !matched {
		t.Fatalf("AuthenticateClientToken() = %t, %v", matched, err)
	}
	matched, err = database.AuthenticateClientToken(ctx, tokenHash("wrong"))
	if err != nil || matched {
		t.Fatalf("wrong token matched = %t, %v", matched, err)
	}
	tokens, err := database.ListClientTokens(ctx)
	if err != nil || len(tokens) != 1 || tokens[0].Label != "Andy" || tokens[0].LastUsedAt == nil {
		t.Fatalf("ListClientTokens() = %#v, %v", tokens, err)
	}
	deleted, err := database.DeleteClientToken(ctx, "token-id")
	if err != nil || !deleted {
		t.Fatalf("DeleteClientToken() = %t, %v", deleted, err)
	}
	matched, err = database.AuthenticateClientToken(ctx, hash)
	if err != nil || matched {
		t.Fatalf("revoked token matched = %t, %v", matched, err)
	}
}

func TestDNSConfigPersists(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "tunnl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	initial, err := database.DNSConfig(ctx)
	if err != nil || initial.Provider != "manual" {
		t.Fatalf("initial DNSConfig() = %#v, %v", initial, err)
	}
	if err := database.SetDNSConfig(ctx, DNSConfig{Provider: "cloudflare", Zone: "tunnl.at", Target: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	configured, err := database.DNSConfig(ctx)
	if err != nil || configured.Provider != "cloudflare" || configured.Zone != "tunnl.at" || configured.Target != "203.0.113.10" || configured.UpdatedAt.Before(time.Now().Add(-time.Minute)) {
		t.Fatalf("configured DNSConfig() = %#v, %v", configured, err)
	}
}

func TestAllocateReservesDomain(t *testing.T) {
	t.Parallel()
	database, err := Open(filepath.Join(t.TempDir(), "tunnl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	owner := tokenHash("owner")
	domain, err := database.Allocate(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	got, err := database.Owner(context.Background(), domain)
	if err != nil || got != owner {
		t.Fatalf("allocated domain owner = %q, %v; want %q", got, err, owner)
	}
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
