package admin

import "time"

type Status struct {
	Version          string    `json:"version"`
	StartedAt        time.Time `json:"started_at"`
	UptimeSeconds    int64     `json:"uptime_seconds"`
	BaseDomain       string    `json:"base_domain"`
	ActiveTunnels    int       `json:"active_tunnels"`
	Reservations     int       `json:"reservations"`
	ManagedTokens    int       `json:"managed_tokens"`
	BootstrapTokens  int       `json:"bootstrap_tokens"`
	TotalConnections uint64    `json:"total_connections"`
	TotalRequests    uint64    `json:"total_requests"`
	FailedRequests   uint64    `json:"failed_requests"`
	ResponseBytes    uint64    `json:"response_bytes"`
	Tunnels          []Tunnel  `json:"tunnels"`
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
