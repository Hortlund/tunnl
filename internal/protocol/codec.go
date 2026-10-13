package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Conn reads and writes control messages on one tunnel stream.
//
// A Conn is not safe for concurrent use. The client writes heartbeats from
// one goroutine after the handshake; the server only reads after it has
// finished writing the welcome message.
type Conn struct {
	r *stickyReader
	w io.Writer
}

// NewConn wraps a QUIC control stream. Reads and writes use the same stream
// in opposite directions.
func NewConn(rw io.ReadWriter) *Conn {
	return &Conn{r: &stickyReader{r: rw}, w: rw}
}

// stickyReader hands bytes back to the next read. json.Decoder fills an
// internal buffer and may pull the start of the next message along with the
// one it returns; those extra bytes have to stay available.
type stickyReader struct {
	r       io.Reader
	pending []byte
}

func (s *stickyReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		if len(s.pending) == 0 {
			s.pending = nil
		}
		return n, nil
	}
	return s.r.Read(p)
}

func (s *stickyReader) unread(b []byte) {
	if len(b) == 0 {
		return
	}
	merged := make([]byte, 0, len(b)+len(s.pending))
	merged = append(merged, b...)
	merged = append(merged, s.pending...)
	s.pending = merged
}

// readValue reads one JSON value, refusing to pull more than MaxFrameSize+1
// bytes from the stream for that value. The extra byte distinguishes a value
// that fills the budget from one that overflows it. Bytes past the value are
// pushed back for the next read.
func (c *Conn) readValue() ([]byte, error) {
	const budget = int64(MaxFrameSize) + 1
	limited := &io.LimitedReader{R: c.r, N: budget}
	dec := json.NewDecoder(limited)
	var raw json.RawMessage
	err := dec.Decode(&raw)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		// LimitedReader turns the byte past the budget into EOF. An incomplete
		// value at that point is an oversized frame, not a short read.
		if budget-limited.N >= budget {
			return nil, ErrFrameTooLarge
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrTruncatedFrame
		}
		return nil, err
	}
	rest, restErr := io.ReadAll(dec.Buffered())
	if restErr != nil {
		return nil, restErr
	}
	c.r.unread(rest)
	if len(raw) > MaxFrameSize {
		return nil, ErrFrameTooLarge
	}
	// Copy out of the decoder buffer. Its cap grows geometrically and would
	// otherwise stay reachable through the returned slice.
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

func (c *Conn) write(v any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		return err
	}
	frame := buf.Bytes()
	if len(frame) == 0 || frame[len(frame)-1] != '\n' || len(frame)-1 > MaxFrameSize {
		return ErrFrameTooLarge
	}
	_, err := c.w.Write(frame)
	return err
}

// ReadHello reads a client handshake.
func (c *Conn) ReadHello() (Hello, error) {
	raw, err := c.readValue()
	if err != nil {
		return Hello{}, err
	}
	return DecodeHello(raw)
}

// ReadWelcome reads a server handshake response.
func (c *Conn) ReadWelcome() (Welcome, error) {
	raw, err := c.readValue()
	if err != nil {
		return Welcome{}, err
	}
	return DecodeWelcome(raw)
}

// ReadControl reads a heartbeat or other control message.
func (c *Conn) ReadControl() (Control, error) {
	raw, err := c.readValue()
	if err != nil {
		return Control{}, err
	}
	return DecodeControl(raw)
}

// WriteHello writes a client handshake.
func (c *Conn) WriteHello(msg Hello) error {
	if len(msg.Token) > MaxFrameSize || len(msg.Domain) > MaxFrameSize || len(msg.Mode) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	return c.write(msg)
}

// WriteWelcome writes a server handshake response.
func (c *Conn) WriteWelcome(msg Welcome) error {
	if len(msg.Error) > MaxFrameSize || len(msg.Domain) > MaxFrameSize || len(msg.URL) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	return c.write(msg)
}

// WriteControl writes a heartbeat or other control message.
func (c *Conn) WriteControl(msg Control) error {
	if len(msg.Type) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	return c.write(msg)
}

// DecodeHello decodes one handshake value that has already been framed.
func DecodeHello(data []byte) (Hello, error) {
	var msg Hello
	if err := decode(data, &msg); err != nil {
		return Hello{}, err
	}
	return msg, nil
}

// DecodeWelcome decodes one handshake response that has already been framed.
func DecodeWelcome(data []byte) (Welcome, error) {
	var msg Welcome
	if err := decode(data, &msg); err != nil {
		return Welcome{}, err
	}
	return msg, nil
}

// DecodeControl decodes one control value that has already been framed.
func DecodeControl(data []byte) (Control, error) {
	var msg Control
	if err := decode(data, &msg); err != nil {
		return Control{}, err
	}
	return msg, nil
}

func decode(data []byte, v any) error {
	if len(data) > MaxFrameSize {
		return ErrFrameTooLarge
	}
	if err := checkDepth(data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// checkDepth rejects deeply nested payloads. Only the first JSON value is
// measured: a byte scan of the whole buffer treats trailing junk such as
// `0[[[[[[[[[` as nesting and hides the syntax error. Invalid JSON is left
// for json.Unmarshal so the caller still sees a syntax error.
func checkDepth(data []byte) error {
	if nestedTooDeep(data) {
		return ErrMessageTooDeep
	}
	return nil
}

// nestedTooDeep reports whether the first JSON value exceeds MaxDepth.
// Invalid JSON returns false so json.Unmarshal can report the syntax error.
func nestedTooDeep(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch delim, _ := tok.(json.Delim); delim {
		case '{', '[':
			depth++
			if depth > MaxDepth {
				return true
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 {
			return false
		}
	}
}
