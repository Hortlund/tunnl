package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var ErrDomainTaken = errors.New("domain is already reserved by another token")

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("configure sqlite: %w", err)
		}
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS domain_reservations (
			domain TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			last_seen_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS domain_reservations_token
			ON domain_reservations(token_hash);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Reserve(ctx context.Context, domain, tokenHash string) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var owner string
	err = tx.QueryRowContext(ctx, "SELECT token_hash FROM domain_reservations WHERE domain = ?", domain).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.ExecContext(ctx, `INSERT INTO domain_reservations(domain, token_hash, created_at, last_seen_at) VALUES (?, ?, ?, ?)`, domain, tokenHash, now, now); err != nil {
			return err
		}
	case err != nil:
		return err
	case owner != tokenHash:
		return ErrDomainTaken
	default:
		if _, err = tx.ExecContext(ctx, "UPDATE domain_reservations SET last_seen_at = ? WHERE domain = ?", now, domain); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var adjectives = []string{"amber", "brisk", "calm", "clever", "cosmic", "gentle", "lucky", "mighty", "polar", "rapid", "silver", "steady"}
var animals = []string{"badger", "falcon", "fox", "koala", "lynx", "otter", "panda", "raven", "tiger", "whale", "wolf", "yak"}

func (s *Store) Allocate(ctx context.Context, tokenHash string) (string, error) {
	for range 32 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		domain := fmt.Sprintf("%s-%s-%04x", adjectives[int(b[0])%len(adjectives)], animals[int(b[1])%len(animals)], uint16(b[2])<<8|uint16(b[3]))
		if err := s.Reserve(ctx, domain, tokenHash); err == nil {
			return domain, nil
		} else if !errors.Is(err, ErrDomainTaken) {
			return "", err
		}
	}
	return "", errors.New("could not allocate an available domain")
}

func (s *Store) Owner(ctx context.Context, domain string) (string, error) {
	var owner string
	err := s.db.QueryRowContext(ctx, "SELECT token_hash FROM domain_reservations WHERE domain = ?", domain).Scan(&owner)
	return owner, err
}
