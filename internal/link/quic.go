package link

import (
	"context"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

// QUIC adapts a quic-go connection to Conn.
type QUIC struct {
	Conn *quic.Conn
}

func (q QUIC) AcceptStream(ctx context.Context) (Stream, error) {
	stream, err := q.Conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return quicStream{stream}, nil
}

func (q QUIC) OpenStreamSync(ctx context.Context) (Stream, error) {
	stream, err := q.Conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return quicStream{stream}, nil
}

func (q QUIC) CloseWithError(code uint64, reason string) error {
	return q.Conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

func (q QUIC) RemoteAddr() net.Addr { return q.Conn.RemoteAddr() }

func (q QUIC) Transport() string { return "quic" }

type quicStream struct{ *quic.Stream }

func (s quicStream) CancelRead(code uint64) { s.Stream.CancelRead(quic.StreamErrorCode(code)) }

func (s quicStream) CancelWrite(code uint64) {
	s.Stream.CancelWrite(quic.StreamErrorCode(code))
}

func (s quicStream) SetReadDeadline(deadline time.Time) error {
	return s.Stream.SetReadDeadline(deadline)
}
