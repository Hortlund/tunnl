package server

import (
	"math"
	"testing"
	"time"
)

func TestMetricsRatesAndBoundedHistory(t *testing.T) {
	t.Parallel()
	values := newMetrics()
	start := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	values.record(start, 1, runtimeSnapshot{totalCPU: 10, idleCPU: 8, heapBytes: 1024, goroutines: 3})
	values.totalRequests.Store(20)
	values.failedRequests.Store(2)
	values.responseBytes.Store(10_000)
	sample := values.record(start.Add(5*time.Second), 2, runtimeSnapshot{totalCPU: 20, idleCPU: 16, heapBytes: 2048, goroutines: 4})
	if sample.RequestsPerSecond != 4 || sample.FailuresPerSecond != 0.4 || sample.BytesPerSecond != 2000 {
		t.Fatalf("unexpected rates: %#v", sample)
	}
	if math.Abs(sample.CPUPercent-20) > 0.001 {
		t.Fatalf("CPU percent = %f, want 20", sample.CPUPercent)
	}
	if sample.ActiveTunnels != 2 || sample.HeapBytes != 2048 || sample.Goroutines != 4 {
		t.Fatalf("unexpected gauges: %#v", sample)
	}
	for index := 2; index <= metricHistoryLimit; index++ {
		values.record(start.Add(time.Duration(index)*time.Second), 0, runtimeSnapshot{})
	}
	history := values.snapshots()
	if len(history) != metricHistoryLimit {
		t.Fatalf("history length = %d, want %d", len(history), metricHistoryLimit)
	}
	if history[0].Timestamp.Equal(start) {
		t.Fatal("oldest sample was not evicted")
	}
}
