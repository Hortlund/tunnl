// Package link is the stream connection used by HTTP and TCP tunnels.
// QUIC and the WebSocket fallback both implement Conn.
package link

import (
	"context"
	"io"
	"net"
	"time"
)

// Stream is one bidirectional tunnel stream.
type Stream interface {
	io.ReadWriteCloser
	CancelRead(uint64)
	CancelWrite(uint64)
	SetReadDeadline(time.Time) error
}

// Conn is one client session. The client opens the control stream.
// The server opens a stream for each proxied HTTP request or TCP connection.
type Conn interface {
	AcceptStream(context.Context) (Stream, error)
	OpenStreamSync(context.Context) (Stream, error)
	CloseWithError(uint64, string) error
	RemoteAddr() net.Addr
	Transport() string
}
