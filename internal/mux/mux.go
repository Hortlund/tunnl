// Package mux multiplexes bidirectional streams over one ordered message transport.
// The WebSocket fallback uses it so the JSON control protocol is unchanged.
// Messages are head-of-line blocked, unlike QUIC streams.
package mux

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Hortlund/tunnl/internal/link"
)

const (
	frameData  byte = 1
	frameOpen  byte = 2
	frameEnd   byte = 3
	frameReset byte = 4

	maxPayload = 32 << 10
	inboxLimit = 32
)

var errStreamClosed = errors.New("tunnel stream closed")

// Messenger is a reliable ordered message pipe, such as a WebSocket.
type Messenger interface {
	ReadMessage(context.Context) ([]byte, error)
	WriteMessage(context.Context, []byte) error
	Close() error
}

// Role decides which stream IDs this side allocates.
type Role int

const (
	Client Role = iota
	Server
)

// Session is a multiplexed link.Conn.
type Session struct {
	ctx      context.Context
	cancel   context.CancelFunc
	messages Messenger
	role     Role
	remote   string

	writeMu sync.Mutex

	mu       sync.Mutex
	streams  map[uint32]*stream
	accept   chan *stream
	nextID   uint32
	closed   bool
	closeErr error
}

// New starts a session. The peer's open frames become AcceptStream results.
func New(parent context.Context, role Role, messages Messenger, remote string) *Session {
	ctx, cancel := context.WithCancel(parent)
	session := &Session{
		ctx:      ctx,
		cancel:   cancel,
		messages: messages,
		role:     role,
		remote:   remote,
		streams:  make(map[uint32]*stream),
		accept:   make(chan *stream, 16),
		nextID:   2,
	}
	if role == Server {
		session.nextID = 1
	}
	go session.readLoop()
	return session
}

func (s *Session) Transport() string { return "websocket" }

func (s *Session) RemoteAddr() net.Addr { return addrString(s.remote) }

type addrString string

func (a addrString) Network() string { return "websocket" }
func (a addrString) String() string  { return string(a) }

func (s *Session) AcceptStream(ctx context.Context) (link.Stream, error) {
	select {
	case stream := <-s.accept:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, io.EOF
	}
}

func (s *Session) OpenStreamSync(ctx context.Context) (link.Stream, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, io.ErrClosedPipe
	}
	id := s.nextID
	s.nextID += 2
	stream := newStream(id, s)
	s.streams[id] = stream
	s.mu.Unlock()
	if err := s.send(ctx, frameOpen, id, nil); err != nil {
		s.drop(stream)
		return nil, err
	}
	return stream, nil
}

func (s *Session) CloseWithError(uint64, string) error {
	s.finish(io.ErrClosedPipe)
	return s.messages.Close()
}

func (s *Session) finish(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.closeErr = err
	streams := s.streams
	s.mu.Unlock()
	s.cancel()
	for _, stream := range streams {
		stream.markReset()
	}
}

func (s *Session) readLoop() {
	defer s.finish(io.EOF)
	for {
		message, err := s.messages.ReadMessage(s.ctx)
		if err != nil {
			return
		}
		if len(message) < 5 || len(message) > 5+maxPayload {
			return
		}
		kind := message[0]
		id := binary.BigEndian.Uint32(message[1:5])
		payload := message[5:]
		switch kind {
		case frameOpen:
			if id == 0 || s.localID(id) {
				return
			}
			stream := s.remoteStream(id)
			if stream == nil {
				return
			}
			select {
			case s.accept <- stream:
			case <-s.ctx.Done():
				return
			}
		case frameData:
			stream := s.existing(id)
			if stream != nil {
				stream.deliver(payload)
			}
		case frameEnd:
			if stream := s.existing(id); stream != nil {
				stream.markEOF()
			}
		case frameReset:
			if stream := s.existing(id); stream != nil {
				stream.markReset()
			}
		default:
			return
		}
	}
}

func (s *Session) localID(id uint32) bool {
	if s.role == Server {
		return id%2 == 1
	}
	return id%2 == 0
}

func (s *Session) remoteStream(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if stream := s.streams[id]; stream != nil {
		return stream
	}
	stream := newStream(id, s)
	s.streams[id] = stream
	return stream
}

func (s *Session) existing(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) drop(stream *stream) {
	s.mu.Lock()
	delete(s.streams, stream.id)
	s.mu.Unlock()
	stream.markReset()
}

func (s *Session) send(ctx context.Context, kind byte, id uint32, payload []byte) error {
	if len(payload) > maxPayload {
		return errors.New("mux payload exceeds limit")
	}
	message := make([]byte, 5+len(payload))
	message[0] = kind
	binary.BigEndian.PutUint32(message[1:5], id)
	copy(message[5:], payload)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.messages.WriteMessage(ctx, message)
}

type stream struct {
	id      uint32
	session *Session
	inbox   chan []byte

	mu       sync.Mutex
	pending  []byte
	deadline time.Time
	eof      bool
	reset    bool
	writeEnd bool
	wake     chan struct{}
}

func newStream(id uint32, session *Session) *stream {
	return &stream{id: id, session: session, inbox: make(chan []byte, inboxLimit), wake: make(chan struct{})}
}

func (s *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if len(s.pending) > 0 {
			n := copy(p, s.pending)
			s.pending = s.pending[n:]
			if len(s.pending) == 0 {
				s.pending = nil
			}
			s.mu.Unlock()
			return n, nil
		}
		reset := s.reset
		eof := s.eof
		deadline := s.deadline
		wake := s.wake
		s.mu.Unlock()
		if reset {
			return 0, errStreamClosed
		}
		if eof {
			select {
			case chunk := <-s.inbox:
				s.mu.Lock()
				s.pending = chunk
				s.mu.Unlock()
				continue
			default:
				return 0, io.EOF
			}
		}

		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			timerC = timer.C
		}
		select {
		case chunk := <-s.inbox:
			stopTimer(timer)
			s.mu.Lock()
			s.pending = chunk
			s.mu.Unlock()
		case <-wake:
			stopTimer(timer)
		case <-timerC:
			return 0, os.ErrDeadlineExceeded
		case <-s.session.ctx.Done():
			stopTimer(timer)
			return 0, errStreamClosed
		}
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func (s *stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.mu.Lock()
		closed := s.writeEnd || s.reset
		s.mu.Unlock()
		if closed {
			return written, errStreamClosed
		}
		n := len(p)
		if n > maxPayload {
			n = maxPayload
		}
		if err := s.session.send(s.session.ctx, frameData, s.id, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (s *stream) Close() error {
	s.mu.Lock()
	if s.writeEnd || s.reset {
		s.mu.Unlock()
		return nil
	}
	s.writeEnd = true
	s.mu.Unlock()
	return s.session.send(context.Background(), frameEnd, s.id, nil)
}

func (s *stream) CancelRead(uint64)  { s.markReset(); _ = s.signalReset() }
func (s *stream) CancelWrite(uint64) { s.markReset(); _ = s.signalReset() }

func (s *stream) signalReset() error {
	return s.session.send(context.Background(), frameReset, s.id, nil)
}

func (s *stream) SetReadDeadline(deadline time.Time) error {
	s.mu.Lock()
	s.deadline = deadline
	old := s.wake
	s.wake = make(chan struct{})
	s.mu.Unlock()
	close(old)
	return nil
}

func (s *stream) deliver(payload []byte) {
	if len(payload) == 0 {
		return
	}
	chunk := append([]byte(nil), payload...)
	select {
	case s.inbox <- chunk:
	case <-s.session.ctx.Done():
	}
}

func (s *stream) markEOF() {
	s.mu.Lock()
	if s.eof || s.reset {
		s.mu.Unlock()
		return
	}
	s.eof = true
	old := s.wake
	s.wake = make(chan struct{})
	s.mu.Unlock()
	close(old)
}

func (s *stream) markReset() {
	s.mu.Lock()
	if s.reset {
		s.mu.Unlock()
		return
	}
	s.reset = true
	old := s.wake
	s.wake = make(chan struct{})
	s.mu.Unlock()
	close(old)
}
