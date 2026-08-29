package server

import (
	"context"
	"sync"

	quic "github.com/quic-go/quic-go"
)

type session struct {
	domain string
	conn   *quic.Conn
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
