package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
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
