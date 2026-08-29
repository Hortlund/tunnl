package server

import (
	"runtime"
	runtimemetrics "runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hortlund/tunnl/internal/admin"
)

const (
	metricSampleInterval = 5 * time.Second
	metricHistoryLimit   = 360
)

type metrics struct {
	startedAt        time.Time
	totalConnections atomic.Uint64
	totalRequests    atomic.Uint64
	failedRequests   atomic.Uint64
	responseBytes    atomic.Uint64
	mu               sync.RWMutex
	history          []admin.MetricSample
	previous         metricCounters
}

type metricCounters struct {
	at       time.Time
	requests uint64
	failures uint64
	bytes    uint64
	totalCPU float64
	idleCPU  float64
}

type runtimeSnapshot struct {
	totalCPU    float64
	idleCPU     float64
	heapBytes   uint64
	systemBytes uint64
	goroutines  int
	gcCycles    uint32
}

func newMetrics() *metrics { return &metrics{startedAt: time.Now().UTC()} }

func (m *metrics) sample(activeTunnels int) admin.MetricSample {
	return m.record(time.Now().UTC(), activeTunnels, readRuntimeSnapshot())
}

func (m *metrics) record(now time.Time, activeTunnels int, runtimeValue runtimeSnapshot) admin.MetricSample {
	current := metricCounters{
		at:       now,
		requests: m.totalRequests.Load(),
		failures: m.failedRequests.Load(),
		bytes:    m.responseBytes.Load(),
		totalCPU: runtimeValue.totalCPU,
		idleCPU:  runtimeValue.idleCPU,
	}
	m.mu.Lock()
	value := admin.MetricSample{Timestamp: now, ActiveTunnels: activeTunnels, HeapBytes: runtimeValue.heapBytes, Goroutines: runtimeValue.goroutines}
	if !m.previous.at.IsZero() {
		elapsed := now.Sub(m.previous.at).Seconds()
		if elapsed > 0 {
			value.RequestsPerSecond = float64(current.requests-m.previous.requests) / elapsed
			value.FailuresPerSecond = float64(current.failures-m.previous.failures) / elapsed
			value.BytesPerSecond = float64(current.bytes-m.previous.bytes) / elapsed
		}
		cpuTotal := current.totalCPU - m.previous.totalCPU
		cpuBusy := cpuTotal - (current.idleCPU - m.previous.idleCPU)
		if cpuTotal > 0 && cpuBusy > 0 {
			value.CPUPercent = cpuBusy / cpuTotal * 100
			if value.CPUPercent > 100 {
				value.CPUPercent = 100
			}
		}
	}
	m.previous = current
	m.history = append(m.history, value)
	if len(m.history) > metricHistoryLimit {
		copy(m.history, m.history[len(m.history)-metricHistoryLimit:])
		m.history = m.history[:metricHistoryLimit]
	}
	m.mu.Unlock()
	return value
}

func (m *metrics) latest() (admin.MetricSample, runtimeSnapshot) {
	m.mu.RLock()
	if len(m.history) > 0 {
		value := m.history[len(m.history)-1]
		m.mu.RUnlock()
		return value, readRuntimeSnapshot()
	}
	m.mu.RUnlock()
	runtimeValue := readRuntimeSnapshot()
	return admin.MetricSample{Timestamp: time.Now().UTC(), HeapBytes: runtimeValue.heapBytes, Goroutines: runtimeValue.goroutines}, runtimeValue
}

func (m *metrics) snapshots() []admin.MetricSample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]admin.MetricSample(nil), m.history...)
}

func readRuntimeSnapshot() runtimeSnapshot {
	samples := []runtimemetrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/cpu/classes/idle:cpu-seconds"},
	}
	runtimemetrics.Read(samples)
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return runtimeSnapshot{
		totalCPU:    samples[0].Value.Float64(),
		idleCPU:     samples[1].Value.Float64(),
		heapBytes:   memory.HeapAlloc,
		systemBytes: memory.Sys,
		goroutines:  runtime.NumGoroutine(),
		gcCycles:    memory.NumGC,
	}
}
