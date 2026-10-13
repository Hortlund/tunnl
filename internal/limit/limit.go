// Package limit provides a small in-process sliding-window rate limiter.
package limit

import (
	"sync"
	"time"
)

// Limiter counts events per key inside a sliding window.
// A non-positive limit disables the limiter.
type Limiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	maxKeys int
	hits    map[string][]time.Time
}

// New returns a limiter that allows limit events per key per window.
func New(limit int, window time.Duration) *Limiter {
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{
		limit:   limit,
		window:  window,
		maxKeys: 10000,
		hits:    make(map[string][]time.Time),
	}
}

// Allow records an event and reports whether it is within the limit.
// Events over the limit are still remembered so repeated abuse stays blocked.
func (l *Limiter) Allow(key string) bool {
	return l.allow(time.Now(), key, true)
}

// Permitted reports whether another event would be allowed.
func (l *Limiter) Permitted(key string) bool {
	return l.allow(time.Now(), key, false)
}

func (l *Limiter) allow(now time.Time, key string, record bool) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > l.maxKeys/2 {
		l.pruneAll(now)
	}
	l.prune(now, key)
	events := l.hits[key]
	if len(events) >= l.limit {
		if record {
			events = append(events, now)
			if len(events) > l.limit {
				events = append([]time.Time(nil), events[len(events)-l.limit:]...)
			}
			l.hits[key] = events
			l.evict()
		}
		return false
	}
	if record {
		l.hits[key] = append(events, now)
		l.evict()
	}
	return true
}

func (l *Limiter) prune(now time.Time, key string) {
	events := l.hits[key]
	cutoff := now.Add(-l.window)
	index := 0
	for index < len(events) && events[index].Before(cutoff) {
		index++
	}
	if index == 0 {
		return
	}
	if index >= len(events) {
		delete(l.hits, key)
		return
	}
	l.hits[key] = append([]time.Time(nil), events[index:]...)
}

func (l *Limiter) pruneAll(now time.Time) {
	for key := range l.hits {
		l.prune(now, key)
	}
}

func (l *Limiter) evict() {
	for len(l.hits) > l.maxKeys {
		for key := range l.hits {
			delete(l.hits, key)
			break
		}
	}
}
