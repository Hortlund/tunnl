package protocol

const (
	Version = 1
	ALPN    = "tunnl/1"
)

type Hello struct {
	Version int    `json:"version"`
	Token   string `json:"token"`
	Domain  string `json:"domain,omitempty"`
	Mode    string `json:"mode"`
}

type Welcome struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Domain string `json:"domain,omitempty"`
	URL    string `json:"url,omitempty"`
}

type Control struct {
	Type string `json:"type"`
}
