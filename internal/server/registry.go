package server

import (
	"context"
	"sort"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type session struct {
	domain      string
	tokenHash   string
	remote      string
	connectedAt time.Time
	conn        *quic.Conn
}

type sessionInfo struct {
	domain      string
	remote      string
	connectedAt time.Time
}

type registry struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

func newRegistry() *registry {
	return &registry{sessions: make(map[string]*session)}
}

func (r *registry) register(value *session) {
	r.mu.Lock()
	previous := r.sessions[value.domain]
	r.sessions[value.domain] = value
	r.mu.Unlock()
	if previous != nil && previous != value {
		_ = previous.conn.CloseWithError(2, "tunnel replaced by a newer connection")
	}
}

func (r *registry) unregister(value *session) {
	r.mu.Lock()
	if r.sessions[value.domain] == value {
		delete(r.sessions, value.domain)
	}
	r.mu.Unlock()
}

func (r *registry) open(ctx context.Context, domain string) (*quic.Stream, error) {
	r.mu.RLock()
	value := r.sessions[domain]
	r.mu.RUnlock()
	if value == nil {
		return nil, errTunnelOffline
	}
	return value.conn.OpenStreamSync(ctx)
}

func (r *registry) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *registry) snapshot() []sessionInfo {
	r.mu.RLock()
	values := make([]sessionInfo, 0, len(r.sessions))
	for _, value := range r.sessions {
		values = append(values, sessionInfo{domain: value.domain, remote: value.remote, connectedAt: value.connectedAt})
	}
	r.mu.RUnlock()
	sort.Slice(values, func(i, j int) bool { return values[i].domain < values[j].domain })
	return values
}

func (r *registry) disconnectToken(tokenHash string) int {
	r.mu.RLock()
	var matches []*session
	for _, value := range r.sessions {
		if value.tokenHash == tokenHash {
			matches = append(matches, value)
		}
	}
	r.mu.RUnlock()
	for _, value := range matches {
		_ = value.conn.CloseWithError(4, "client token revoked")
	}
	return len(matches)
}
