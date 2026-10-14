// Package wsock is a small RFC 6455 client and server for binary messages.
// It is the tunnel fallback transport and only implements the frames tunnl uses.
package wsock

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	guid        = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxMessage  = 1 << 20
	opcodeBin   = 0x2
	opcodeClose = 0x8
	opcodePing  = 0x9
	opcodePong  = 0xA
)

var errBadHandshake = errors.New("websocket handshake failed")

// Conn is one WebSocket connection that exchanges binary messages.
type Conn struct {
	conn      net.Conn
	reader    *bufio.Reader
	writer    io.Writer
	closer    io.Closer
	masked    bool
	writeMu   sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

// Adapter exposes Conn as a context-aware message pipe.
type Adapter struct{ *Conn }

func (a Adapter) ReadMessage(context.Context) ([]byte, error) { return a.Conn.ReadMessage() }

func (a Adapter) WriteMessage(_ context.Context, payload []byte) error {
	return a.Conn.WriteMessage(payload)
}

func (a Adapter) Close() error { return a.Conn.Close() }

// Dial opens a WebSocket. tlsConfig nil means plain TCP.
func Dial(network, address, host, path string, tlsConfig *tls.Config, timeout time.Duration) (*Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	raw, err := dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}
	conn := raw
	if tlsConfig != nil {
		tlsConn := tls.Client(raw, tlsConfig)
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			raw.Close()
			return nil, err
		}
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			raw.Close()
			return nil, err
		}
		conn = tlsConn
	}
	ws, err := Client(conn, host, path)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ws, nil
}

// Client completes a client handshake on an existing connection.
func Client(conn net.Conn, host, path string) (*Conn, error) {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host, key)
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	status, headers, err := readHandshake(reader)
	if err != nil {
		return nil, err
	}
	if status != http.StatusSwitchingProtocols || !headerValue(headers, "Upgrade", "websocket") || acceptKey(key) != headers.Get("Sec-WebSocket-Accept") {
		return nil, errBadHandshake
	}
	return &Conn{conn: conn, reader: reader, writer: conn, closer: conn, masked: true}, nil
}

// Accept writes the server handshake on an already-hijacked connection.
func Accept(conn net.Conn, reader *bufio.Reader, writer io.Writer, key string) (*Conn, error) {
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	if writer == nil {
		writer = conn
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + acceptKey(key) + "\r\n\r\n"
	if _, err := io.WriteString(writer, response); err != nil {
		return nil, err
	}
	if flusher, ok := writer.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			return nil, err
		}
	}
	return &Conn{conn: conn, reader: reader, writer: writer, closer: conn, masked: false}, nil
}

func (c *Conn) ReadMessage() ([]byte, error) {
	var assembled []byte
	var opcode byte
	for {
		fin, op, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch op {
		case opcodePing:
			if err := c.writeFrame(opcodePong, payload); err != nil {
				return nil, err
			}
			continue
		case opcodePong:
			continue
		case opcodeClose:
			return nil, io.EOF
		case 0:
			if opcode == 0 {
				return nil, errors.New("websocket continuation without a start frame")
			}
			assembled = append(assembled, payload...)
		default:
			opcode = op
			assembled = append([]byte(nil), payload...)
		}
		if len(assembled) > maxMessage {
			return nil, errors.New("websocket message exceeds limit")
		}
		if fin {
			if opcode != opcodeBin {
				return nil, errors.New("websocket message is not binary")
			}
			return assembled, nil
		}
	}
}

func (c *Conn) WriteMessage(payload []byte) error {
	if len(payload) > maxMessage {
		return errors.New("websocket message exceeds limit")
	}
	return c.writeFrame(opcodeBin, payload)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.writeFrame(opcodeClose, []byte{})
		c.closeErr = c.closer.Close()
	})
	return c.closeErr
}

func (c *Conn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	header := make([]byte, 2)
	if _, err = io.ReadFull(c.reader, header); err != nil {
		return false, 0, nil, err
	}
	fin = header[0]&0x80 != 0
	opcode = header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		extended := make([]byte, 2)
		if _, err = io.ReadFull(c.reader, extended); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended))
	case 127:
		extended := make([]byte, 8)
		if _, err = io.ReadFull(c.reader, extended); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended)
	}
	if length > maxMessage {
		return false, 0, nil, errors.New("websocket frame exceeds limit")
	}
	if c.masked && masked {
		return false, 0, nil, errors.New("server frame was masked")
	}
	if !c.masked && !masked {
		return false, 0, nil, errors.New("client frame was not masked")
	}
	var mask [4]byte
	if masked {
		if _, err = io.ReadFull(c.reader, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(c.reader, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}

func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	header := []byte{0x80 | opcode, 0}
	if c.masked {
		header[1] |= 0x80
	}
	length := len(payload)
	switch {
	case length < 126:
		header[1] |= byte(length)
	case length <= 65535:
		header[1] |= 126
		header = append(header, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(length))
	default:
		header[1] |= 127
		header = append(header, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(length))
	}
	var mask [4]byte
	if c.masked {
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		header = append(header, mask[:]...)
		payload = append([]byte(nil), payload...)
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if _, err := c.writer.Write(header); err != nil {
		return err
	}
	if flusher, ok := c.writer.(interface{ Flush() error }); ok && len(payload) == 0 {
		if err := flusher.Flush(); err != nil {
			return err
		}
	}
	_, err := c.writer.Write(payload)
	if err != nil {
		return err
	}
	if flusher, ok := c.writer.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func readHandshake(reader *bufio.Reader) (int, http.Header, error) {
	line, err := readLimitedLine(reader, 256)
	if err != nil {
		return 0, nil, err
	}
	var status int
	if _, err := fmt.Sscanf(line, "HTTP/1.1 %d", &status); err != nil {
		return 0, nil, errBadHandshake
	}
	headers := make(http.Header)
	for {
		line, err := readLimitedLine(reader, 8<<10)
		if err != nil {
			return 0, nil, err
		}
		if line == "" {
			return status, headers, nil
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return 0, nil, errBadHandshake
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
}

func readLimitedLine(reader *bufio.Reader, limit int) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > limit {
		return "", errors.New("websocket handshake line is too long")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func headerValue(headers http.Header, name, want string) bool {
	return strings.EqualFold(strings.TrimSpace(headers.Get(name)), want)
}
