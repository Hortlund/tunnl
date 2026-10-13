package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRoundTripMessages(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		write func(*Conn) error
		read  func(*Conn) (any, error)
		want  any
	}{
		{
			name: "hello",
			write: func(c *Conn) error {
				return c.WriteHello(Hello{Version: Version, Token: "tnl_secret", Domain: "demo", Mode: "http"})
			},
			read: func(c *Conn) (any, error) {
				msg, err := c.ReadHello()
				return msg, err
			},
			want: Hello{Version: Version, Token: "tnl_secret", Domain: "demo", Mode: "http"},
		},
		{
			name: "hello without domain",
			write: func(c *Conn) error {
				return c.WriteHello(Hello{Version: Version, Token: "abc", Mode: "http"})
			},
			read: func(c *Conn) (any, error) {
				msg, err := c.ReadHello()
				return msg, err
			},
			want: Hello{Version: Version, Token: "abc", Mode: "http"},
		},
		{
			name: "welcome",
			write: func(c *Conn) error {
				return c.WriteWelcome(Welcome{OK: true, Domain: "demo", URL: "https://demo.tunnl.test"})
			},
			read: func(c *Conn) (any, error) {
				msg, err := c.ReadWelcome()
				return msg, err
			},
			want: Welcome{OK: true, Domain: "demo", URL: "https://demo.tunnl.test"},
		},
		{
			name: "welcome error",
			write: func(c *Conn) error {
				return c.WriteWelcome(Welcome{Error: "authentication failed"})
			},
			read: func(c *Conn) (any, error) {
				msg, err := c.ReadWelcome()
				return msg, err
			},
			want: Welcome{Error: "authentication failed"},
		},
		{
			name: "control",
			write: func(c *Conn) error {
				return c.WriteControl(Control{Type: "ping"})
			},
			read: func(c *Conn) (any, error) {
				msg, err := c.ReadControl()
				return msg, err
			},
			want: Control{Type: "ping"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := test.write(NewConn(&buf)); err != nil {
				t.Fatal(err)
			}
			got, err := test.read(readConn(bytes.NewReader(buf.Bytes())))
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestWriteMatchesJSONEncoder(t *testing.T) {
	t.Parallel()
	messages := []any{
		Hello{Version: 1, Token: `a&b<c>d`, Domain: "demo", Mode: "http"},
		Welcome{OK: true, Domain: "demo", URL: "https://demo.tunnl.test/a?b=1&c=2"},
		Welcome{Error: "domain is reserved"},
		Control{Type: "ping"},
	}
	for _, msg := range messages {
		var std bytes.Buffer
		if err := json.NewEncoder(&std).Encode(msg); err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		conn := NewConn(&got)
		var err error
		switch typed := msg.(type) {
		case Hello:
			err = conn.WriteHello(typed)
		case Welcome:
			err = conn.WriteWelcome(typed)
		case Control:
			err = conn.WriteControl(typed)
		default:
			t.Fatalf("unexpected %T", msg)
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), std.Bytes()) {
			t.Fatalf("wire bytes = %q, encoder = %q", got.Bytes(), std.Bytes())
		}
		dec := json.NewDecoder(bytes.NewReader(got.Bytes()))
		switch msg.(type) {
		case Hello:
			var out Hello
			if err := dec.Decode(&out); err != nil || out != msg {
				t.Fatalf("stdlib decode = %#v, %v", out, err)
			}
		case Welcome:
			var out Welcome
			if err := dec.Decode(&out); err != nil || out != msg {
				t.Fatalf("stdlib decode = %#v, %v", out, err)
			}
		case Control:
			var out Control
			if err := dec.Decode(&out); err != nil || out != msg {
				t.Fatalf("stdlib decode = %#v, %v", out, err)
			}
		}
	}
}

func TestSequentialMessagesAndPushback(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	writer := NewConn(&buf)
	if err := writer.WriteHello(Hello{Version: 1, Token: "secret", Mode: "http"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteControl(Control{Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteControl(Control{Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	// Both values fit in one decoder refill. The second must survive pushback.
	reader := NewConn(&oneByteReader{b: buf.Bytes()})
	hello, err := reader.ReadHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.Token != "secret" || hello.Mode != "http" {
		t.Fatalf("hello = %#v", hello)
	}
	for range 2 {
		control, err := reader.ReadControl()
		if err != nil {
			t.Fatal(err)
		}
		if control.Type != "ping" {
			t.Fatalf("control = %#v", control)
		}
	}
	if _, err := reader.ReadControl(); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing read = %v, want EOF", err)
	}
}

func TestAcceptsStdlibJSONShapes(t *testing.T) {
	t.Parallel()
	hello := Hello{Version: 1, Token: "secret", Domain: "demo", Mode: "http"}
	var pretty bytes.Buffer
	enc := json.NewEncoder(&pretty)
	enc.SetIndent("", "  ")
	if err := enc.Encode(hello); err != nil {
		t.Fatal(err)
	}
	compact, err := json.Marshal(hello)
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{
		pretty.Bytes(),
		compact, // no trailing newline
		append([]byte(" \t\r\n"), append(compact, '\n')...),
		[]byte("{\"version\":1,\"token\":\"a{\\\"b[c]\\\"}\",\"mode\":\"http\"}\n"),
	}
	for _, input := range inputs {
		got, err := readConn(bytes.NewReader(input)).ReadHello()
		if err != nil {
			t.Fatalf("ReadHello(%q) error = %v", input, err)
		}
		if got.Version != 1 || got.Mode != "http" || got.Token == "" {
			t.Fatalf("ReadHello(%q) = %#v", input, got)
		}
	}
}

func TestMalformedAndTruncatedInput(t *testing.T) {
	t.Parallel()
	syntax := [][]byte{
		[]byte(`{`),
		[]byte(`{"version":`),
		[]byte(`{"version":1,}`),
		[]byte(`not-json`),
		[]byte(`["http"]`),
		[]byte(`"ping"`),
		[]byte(`{"version":true}`),
		{0xff, 0xfe, '{'},
	}
	for _, input := range syntax {
		if _, err := DecodeHello(input); err == nil {
			t.Fatalf("DecodeHello(%q) succeeded", input)
		}
		_, err := readConn(bytes.NewReader(input)).ReadHello()
		if err == nil {
			t.Fatalf("ReadHello(%q) succeeded", input)
		}
	}
	// A second value on the same stream is the next message, not a syntax error.
	if _, err := DecodeHello([]byte(`{"version":1,"token":"t","mode":"http"}{"type":"ping"}`)); err == nil {
		t.Fatal("DecodeHello accepted trailing data")
	}
	stream := readConn(strings.NewReader(`{"version":1,"token":"t","mode":"http"}{"type":"ping"}`))
	if _, err := stream.ReadHello(); err != nil {
		t.Fatal(err)
	}
	control, err := stream.ReadControl()
	if err != nil || control.Type != "ping" {
		t.Fatalf("second value = %#v, %v", control, err)
	}

	truncated := [][]byte{
		[]byte(`{`),
		[]byte(`{"version":1`),
		[]byte(`{"type":"pi`),
	}
	for _, input := range truncated {
		_, err := readConn(bytes.NewReader(input)).ReadHello()
		if !errors.Is(err, ErrTruncatedFrame) && !errors.As(err, new(*json.SyntaxError)) {
			// A truncated token can be a syntax error once the stream ends
			// inside a literal, or a truncated frame inside a container.
			if err == nil {
				t.Fatalf("ReadHello(%q) succeeded", input)
			}
		}
	}
	if _, err := readConn(bytes.NewReader(nil)).ReadHello(); !errors.Is(err, io.EOF) {
		t.Fatalf("empty stream error = %v, want EOF", err)
	}
	if _, err := readConn(strings.NewReader(" \r\n\t")).ReadHello(); !errors.Is(err, io.EOF) {
		t.Fatalf("whitespace stream error = %v, want EOF", err)
	}
}

func TestNullAndUnknownFields(t *testing.T) {
	t.Parallel()
	hello, err := DecodeHello([]byte(`null`))
	if err != nil || hello != (Hello{}) {
		t.Fatalf("null hello = %#v, %v", hello, err)
	}
	hello, err = DecodeHello([]byte(`{"version":1,"token":"t","mode":"http","future":{"ok":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if hello != (Hello{Version: 1, Token: "t", Mode: "http"}) {
		t.Fatalf("unknown field hello = %#v", hello)
	}
	// encoding/json keeps the last duplicate key.
	hello, err = DecodeHello([]byte(`{"version":1,"token":"first","token":"second","mode":"http"}`))
	if err != nil {
		t.Fatal(err)
	}
	if hello.Token != "second" {
		t.Fatalf("token = %q", hello.Token)
	}
}

func TestBoundaryFrameSize(t *testing.T) {
	t.Parallel()
	exact := helloBytes(t, MaxFrameSize)
	got, err := DecodeHello(exact)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Mode != "http" || len(got.Token) == 0 {
		t.Fatalf("decoded = %#v", got)
	}
	stream := append(append([]byte{}, exact...), []byte(`{"type":"ping"}`)...)
	conn := readConn(bytes.NewReader(stream))
	if _, err := conn.ReadHello(); err != nil {
		t.Fatal(err)
	}
	control, err := conn.ReadControl()
	if err != nil {
		t.Fatal(err)
	}
	if control.Type != "ping" {
		t.Fatalf("control = %#v", control)
	}

	over := helloBytes(t, MaxFrameSize+1)
	if _, err := DecodeHello(over); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("DecodeHello oversized = %v", err)
	}
	if _, err := readConn(bytes.NewReader(over)).ReadHello(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadHello oversized = %v", err)
	}
}

func TestOversizedFrameDoesNotReadPastBudget(t *testing.T) {
	t.Parallel()
	prefix := []byte(`{"version":1,"token":"`)
	quota := &quotaReader{n: MaxFrameSize + 64, b: 'a'}
	conn := readConn(io.MultiReader(bytes.NewReader(prefix), quota))
	_, err := conn.ReadHello()
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v, want ErrFrameTooLarge", err)
	}
	read := len(prefix) + (MaxFrameSize + 64 - quota.n)
	if read > MaxFrameSize+1 {
		t.Fatalf("read %d bytes, budget %d", read, MaxFrameSize+1)
	}
	if quota.n == 0 {
		t.Fatal("underlying reader was drained past the frame budget")
	}
}

func TestOversizedWriteWritesNothing(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	conn := NewConn(&buf)
	err := conn.WriteHello(Hello{Version: 1, Token: strings.Repeat("a", MaxFrameSize+1), Mode: "http"})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %d bytes", buf.Len())
	}
	// The token itself fits, but the JSON object does not.
	err = conn.WriteHello(Hello{Version: 1, Token: strings.Repeat("a", MaxFrameSize-10), Mode: "http"})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("encoded overflow error = %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %d bytes after encoded overflow", buf.Len())
	}
}

func TestTrailingJunkIsNotNesting(t *testing.T) {
	t.Parallel()
	// Fuzz found this: a number followed by brackets is invalid JSON of depth 0.
	// Counting every '[' in the buffer reported a nesting error instead.
	_, err := DecodeHello([]byte("0[[[[[[[[["))
	if errors.Is(err, ErrMessageTooDeep) {
		t.Fatal("trailing brackets were reported as message nesting")
	}
	if err == nil {
		t.Fatal("accepted invalid JSON")
	}
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("error = %v, want a JSON syntax error", err)
	}
}

func TestNestingLimit(t *testing.T) {
	t.Parallel()
	if _, err := DecodeHello([]byte(nestedHello(MaxDepth))); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeHello([]byte(nestedHello(MaxDepth + 1))); !errors.Is(err, ErrMessageTooDeep) {
		t.Fatalf("deep hello error = %v", err)
	}
	// Braces inside a string are data, not nesting.
	token := strings.Repeat("{", 100) + strings.Repeat("[", 100)
	raw := `{"version":1,"token":"` + token + `","mode":"http"}`
	got, err := DecodeHello([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != token {
		t.Fatalf("token = %q", got.Token)
	}
	escaped := `{"version":1,"token":"a\"{b\\c","mode":"http"}`
	got, err = DecodeHello([]byte(escaped))
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != `a"{b\c` {
		t.Fatalf("token = %q", got.Token)
	}
}

func TestChunkedReads(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	writer := NewConn(&buf)
	if err := writer.WriteWelcome(Welcome{OK: true, Domain: "demo", URL: "https://demo.tunnl.test"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteControl(Control{Type: "ping"}); err != nil {
		t.Fatal(err)
	}
	conn := NewConn(&chunkReader{b: buf.Bytes(), n: 3})
	welcome, err := conn.ReadWelcome()
	if err != nil {
		t.Fatal(err)
	}
	if !welcome.OK || welcome.Domain != "demo" {
		t.Fatalf("welcome = %#v", welcome)
	}
	control, err := conn.ReadControl()
	if err != nil {
		t.Fatal(err)
	}
	if control.Type != "ping" {
		t.Fatalf("control = %#v", control)
	}
}

func readConn(r io.Reader) *Conn {
	if rw, ok := r.(io.ReadWriter); ok {
		return NewConn(rw)
	}
	return NewConn(readWriter{Reader: r, Writer: io.Discard})
}

type readWriter struct {
	io.Reader
	io.Writer
}

func helloBytes(t testing.TB, size int) []byte {
	t.Helper()
	const prefix = `{"version":1,"token":"`
	const suffix = `","mode":"http"}`
	n := size - len(prefix) - len(suffix)
	if n < 1 {
		t.Fatalf("size %d is too small", size)
	}
	body := make([]byte, 0, size)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("a"), n)...)
	body = append(body, suffix...)
	if len(body) != size {
		t.Fatalf("constructed %d bytes, want %d", len(body), size)
	}
	return body
}

func nestedHello(depth int) string {
	if depth <= 1 {
		return `{"version":1,"token":"t","mode":"http"}`
	}
	inner := `1`
	for range depth - 1 {
		inner = `{"k":` + inner + `}`
	}
	return `{"version":1,"token":"t","mode":"http","n":` + inner + `}`
}

type oneByteReader struct {
	b []byte
	i int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	p[0] = r.b[r.i]
	r.i++
	return 1, nil
}

func (r *oneByteReader) Write(p []byte) (int, error) { return len(p), nil }

type chunkReader struct {
	b []byte
	n int
	i int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := r.n
	if n > len(p) {
		n = len(p)
	}
	if n > len(r.b)-r.i {
		n = len(r.b) - r.i
	}
	copy(p[:n], r.b[r.i:r.i+n])
	r.i += n
	return n, nil
}

func (r *chunkReader) Write(p []byte) (int, error) { return len(p), nil }

type quotaReader struct {
	n int
	b byte
}

func (r *quotaReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("read past quota")
	}
	if len(p) > r.n {
		p = p[:r.n]
	}
	for i := range p {
		p[i] = r.b
	}
	r.n -= len(p)
	return len(p), nil
}

func (r *quotaReader) Write(p []byte) (int, error) { return len(p), nil }
