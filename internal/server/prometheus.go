package server

import (
	"fmt"
	"io"

	"github.com/Hortlund/tunnl/internal/version"
)

func writePrometheus(writer io.Writer, metrics *metrics, active int) {
	writeCounter(writer, "tunnl_tunnels_active", "Active tunnel sessions.", "gauge", uint64(active))
	writeCounter(writer, "tunnl_connections_total", "Tunnel sessions that completed the handshake.", "counter", metrics.totalConnections.Load())
	writeCounter(writer, "tunnl_requests_total", "Public HTTP requests received.", "counter", metrics.totalRequests.Load())
	writeCounter(writer, "tunnl_request_failures_total", "Public HTTP requests that were not proxied successfully.", "counter", metrics.failedRequests.Load())
	writeCounter(writer, "tunnl_response_bytes_total", "Response body bytes copied from tunnels.", "counter", metrics.responseBytes.Load())
	writeCounter(writer, "tunnl_handshake_failures_total", "QUIC handshakes that failed before a tunnel was registered.", "counter", metrics.handshakeFailures.Load())
	writeCounter(writer, "tunnl_accepts_rejected_total", "QUIC connections rejected by the accept or handshake rate limit.", "counter", metrics.rejectedAccepts.Load())
	fmt.Fprintf(writer, "# HELP tunnl_build_info Build information.\n# TYPE tunnl_build_info gauge\n")
	fmt.Fprintf(writer, "tunnl_build_info{version=%q,commit=%q} 1\n", version.Version, version.Commit)
}

func writeCounter(writer io.Writer, name, help, kind string, value uint64) {
	fmt.Fprintf(writer, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, kind, name, value)
}
