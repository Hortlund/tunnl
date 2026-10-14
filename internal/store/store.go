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

type ClientToken struct {
	ID         string
	Label      string
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

type DNSConfig struct {
	Provider  string
	Zone      string
	Target    string
	UpdatedAt time.Time
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
		CREATE TABLE IF NOT EXISTS client_tokens (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			prefix TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			last_used_at INTEGER
		);
		CREATE TABLE IF NOT EXISTS dns_config (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			provider TEXT NOT NULL,
			zone TEXT NOT NULL,
			target TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS tcp_ports (
			port INTEGER PRIMARY KEY,
			token_hash TEXT NOT NULL,
			label TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(token_hash, label)
		);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) Reserve(ctx context.Context, domain, tokenHash string) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
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

func (s *Store) CountReservations(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domain_reservations").Scan(&count)
	return count, err
}

func (s *Store) CreateClientToken(ctx context.Context, id, label, tokenHash, prefix string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO client_tokens(id, label, token_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?)`, id, label, tokenHash, prefix, time.Now().Unix())
	return err
}

func (s *Store) AuthenticateClientToken(ctx context.Context, tokenHash string) (bool, error) {
	result, err := s.db.ExecContext(ctx, "UPDATE client_tokens SET last_used_at = ? WHERE token_hash = ?", time.Now().Unix(), tokenHash)
	if err != nil {
		return false, err
	}
	matched, err := result.RowsAffected()
	return matched == 1, err
}

func (s *Store) ListClientTokens(ctx context.Context) ([]ClientToken, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, label, prefix, created_at, last_used_at FROM client_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []ClientToken
	for rows.Next() {
		var token ClientToken
		var createdAt int64
		var lastUsedAt sql.NullInt64
		if err := rows.Scan(&token.ID, &token.Label, &token.Prefix, &createdAt, &lastUsedAt); err != nil {
			return nil, err
		}
		token.CreatedAt = time.Unix(createdAt, 0).UTC()
		if lastUsedAt.Valid {
			value := time.Unix(lastUsedAt.Int64, 0).UTC()
			token.LastUsedAt = &value
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *Store) DeleteClientToken(ctx context.Context, id string) (bool, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM client_tokens WHERE id = ?", id)
	if err != nil {
		return false, err
	}
	deleted, err := result.RowsAffected()
	return deleted == 1, err
}

func (s *Store) ClientTokenHash(ctx context.Context, id string) (string, error) {
	var tokenHash string
	err := s.db.QueryRowContext(ctx, "SELECT token_hash FROM client_tokens WHERE id = ?", id).Scan(&tokenHash)
	return tokenHash, err
}

func (s *Store) CountClientTokens(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM client_tokens").Scan(&count)
	return count, err
}

func (s *Store) DNSConfig(ctx context.Context) (DNSConfig, error) {
	var config DNSConfig
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, "SELECT provider, zone, target, updated_at FROM dns_config WHERE id = 1").Scan(&config.Provider, &config.Zone, &config.Target, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DNSConfig{Provider: "manual"}, nil
	}
	if err != nil {
		return DNSConfig{}, err
	}
	config.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return config, nil
}

func (s *Store) LookupTCP(ctx context.Context, tokenHash, label string) (int, bool, error) {
	var port int
	err := s.db.QueryRowContext(ctx, "SELECT port FROM tcp_ports WHERE token_hash = ? AND label = ?", tokenHash, label).Scan(&port)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return port, true, nil
}

func (s *Store) TCPPorts(ctx context.Context) (map[int]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT port, token_hash FROM tcp_ports")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ports := make(map[int]string)
	for rows.Next() {
		var port int
		var tokenHash string
		if err := rows.Scan(&port, &tokenHash); err != nil {
			return nil, err
		}
		ports[port] = tokenHash
	}
	return ports, rows.Err()
}

func (s *Store) CountTCP(ctx context.Context, tokenHash string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tcp_ports WHERE token_hash = ?", tokenHash).Scan(&count)
	return count, err
}

func (s *Store) SaveTCP(ctx context.Context, port int, tokenHash, label string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "DELETE FROM tcp_ports WHERE token_hash = ? AND label = ? AND port <> ?", tokenHash, label, port); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tcp_ports(port, token_hash, label, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(port) DO UPDATE SET token_hash = excluded.token_hash, label = excluded.label
		WHERE tcp_ports.token_hash = excluded.token_hash
	`, port, tokenHash, label, time.Now().Unix()); err != nil {
		return err
	}
	var owner string
	if err := tx.QueryRowContext(ctx, "SELECT token_hash FROM tcp_ports WHERE port = ?", port).Scan(&owner); err != nil {
		return err
	}
	if owner != tokenHash {
		return errors.New("tcp port is reserved")
	}
	return tx.Commit()
}

func (s *Store) DeleteTCPPort(ctx context.Context, port int) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM tcp_ports WHERE port = ?", port)
	return err
}

func (s *Store) DeleteTCPByToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM tcp_ports WHERE token_hash = ?", tokenHash)
	return err
}

func (s *Store) SetDNSConfig(ctx context.Context, config DNSConfig) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO dns_config(id, provider, zone, target, updated_at)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET provider = excluded.provider, zone = excluded.zone, target = excluded.target, updated_at = excluded.updated_at
	`, config.Provider, config.Zone, config.Target, time.Now().Unix())
	return err
}
