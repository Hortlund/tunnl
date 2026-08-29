package server

import (
	"sync/atomic"
	"time"
)

type metrics struct {
	startedAt        time.Time
	totalConnections atomic.Uint64
	totalRequests    atomic.Uint64
	failedRequests   atomic.Uint64
	responseBytes    atomic.Uint64
}

func newMetrics() *metrics { return &metrics{startedAt: time.Now().UTC()} }
