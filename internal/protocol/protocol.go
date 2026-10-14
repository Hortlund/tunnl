// Package protocol is the tunnl control stream: a versioned JSON handshake
// followed by heartbeat messages. Each value is a single JSON object, as
// produced by encoding/json.Encoder, and is limited to MaxFrameSize bytes.
package protocol

import "errors"

const (
	Version = 1
	ALPN    = "tunnl/1"

	// WebSocketPath is the HTTPS request path for the fallback transport.
	WebSocketPath = "/_tunnl/ws"

	// MaxFrameSize is the maximum size of one control value in bytes.
	// Handshake and heartbeat messages are small. The cap stops a peer from
	// forcing the process to buffer an arbitrarily large JSON value.
	MaxFrameSize = 64 << 10

	// MaxDepth is the deepest object or array nesting accepted in a control
	// message. Legitimate messages are flat objects.
	MaxDepth = 8
)

var (
	// ErrFrameTooLarge is returned when a control value exceeds MaxFrameSize.
	ErrFrameTooLarge = errors.New("protocol frame exceeds size limit")
	// ErrTruncatedFrame is returned when the stream ends inside a control value.
	ErrTruncatedFrame = errors.New("truncated protocol frame")
	// ErrMessageTooDeep is returned when nesting exceeds MaxDepth.
	ErrMessageTooDeep = errors.New("protocol message nested too deeply")
)

type Hello struct {
	Version int    `json:"version"`
	Token   string `json:"token"`
	Domain  string `json:"domain,omitempty"`
	Mode    string `json:"mode"`
	Label   string `json:"label,omitempty"`
}

type Welcome struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Domain string `json:"domain,omitempty"`
	URL    string `json:"url,omitempty"`
	Port   int    `json:"port,omitempty"`
}

type Control struct {
	Type string `json:"type"`
}
