package admin

import "time"

type Status struct {
	Version          string            `json:"version"`
	StartedAt        time.Time         `json:"started_at"`
	UptimeSeconds    int64             `json:"uptime_seconds"`
	BaseDomain       string            `json:"base_domain"`
	ActiveTunnels    int               `json:"active_tunnels"`
	Reservations     int               `json:"reservations"`
	ManagedTokens    int               `json:"managed_tokens"`
	BootstrapTokens  int               `json:"bootstrap_tokens"`
	TotalConnections uint64            `json:"total_connections"`
	TotalRequests    uint64            `json:"total_requests"`
	FailedRequests   uint64            `json:"failed_requests"`
	ResponseBytes    uint64            `json:"response_bytes"`
	System           SystemStatus      `json:"system"`
	Certificate      CertificateStatus `json:"certificate"`
	Tunnels          []Tunnel          `json:"tunnels"`
}

type SystemStatus struct {
	CPUPercent     float64 `json:"cpu_percent"`
	HeapBytes      uint64  `json:"heap_bytes"`
	RuntimeBytes   uint64  `json:"runtime_bytes"`
	Goroutines     int     `json:"goroutines"`
	GCCycles       uint32  `json:"gc_cycles"`
	DatabaseBytes  int64   `json:"database_bytes"`
	DiskTotalBytes uint64  `json:"disk_total_bytes,omitempty"`
	DiskFreeBytes  uint64  `json:"disk_free_bytes,omitempty"`
	NumCPU         int     `json:"num_cpu"`
	GoVersion      string  `json:"go_version"`
}

type CertificateStatus struct {
	Mode               string     `json:"mode"`
	State              string     `json:"state"`
	Provider           string     `json:"provider,omitempty"`
	Staging            bool       `json:"staging"`
	Names              []string   `json:"names,omitempty"`
	Issuer             string     `json:"issuer,omitempty"`
	Serial             string     `json:"serial,omitempty"`
	NotBefore          *time.Time `json:"not_before,omitempty"`
	NotAfter           *time.Time `json:"not_after,omitempty"`
	RenewalWindowStart *time.Time `json:"renewal_window_start,omitempty"`
	LastEvent          string     `json:"last_event,omitempty"`
	LastEventAt        *time.Time `json:"last_event_at,omitempty"`
	LastError          string     `json:"last_error,omitempty"`
}

type Metrics struct {
	WindowSeconds         int64          `json:"window_seconds"`
	SampleIntervalSeconds int64          `json:"sample_interval_seconds"`
	Samples               []MetricSample `json:"samples"`
}

type MetricSample struct {
	Timestamp         time.Time `json:"timestamp"`
	ActiveTunnels     int       `json:"active_tunnels"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	FailuresPerSecond float64   `json:"failures_per_second"`
	BytesPerSecond    float64   `json:"bytes_per_second"`
	CPUPercent        float64   `json:"cpu_percent"`
	HeapBytes         uint64    `json:"heap_bytes"`
	Goroutines        int       `json:"goroutines"`
}

type Tunnel struct {
	Domain      string    `json:"domain"`
	Remote      string    `json:"remote"`
	ConnectedAt time.Time `json:"connected_at"`
}

type Token struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type CreateTokenRequest struct {
	Label string `json:"label"`
}

type CreatedToken struct {
	Token
	Secret string `json:"secret"`
}

type DNSConfig struct {
	Provider            string    `json:"provider"`
	Zone                string    `json:"zone"`
	Target              string    `json:"target"`
	CredentialAvailable bool      `json:"credential_available"`
	UpdatedAt           time.Time `json:"updated_at,omitempty"`
}

type OperationResult struct {
	Message string `json:"message"`
}
