package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func FuzzDecodeHello(f *testing.F) {
	seedDecode(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeHello(data)
		assertDecoded(t, data, err, func() error {
			var want Hello
			wantErr := json.Unmarshal(data, &want)
			if err == nil && wantErr == nil && got != want {
				t.Fatalf("DecodeHello = %#v, stdlib = %#v", got, want)
			}
			return wantErr
		})
	})
}

func FuzzDecodeWelcome(f *testing.F) {
	seedDecode(f)
	f.Add([]byte(`{"ok":true,"domain":"demo","url":"https://demo.tunnl.test"}`))
	f.Add([]byte(`{"ok":false,"error":"authentication failed"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeWelcome(data)
		assertDecoded(t, data, err, func() error {
			var want Welcome
			wantErr := json.Unmarshal(data, &want)
			if err == nil && wantErr == nil && got != want {
				t.Fatalf("DecodeWelcome = %#v, stdlib = %#v", got, want)
			}
			return wantErr
		})
	})
}

func FuzzDecodeControl(f *testing.F) {
	seedDecode(f)
	f.Add([]byte(`{"type":"ping"}`))
	f.Add([]byte(`{"type":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodeControl(data)
		assertDecoded(t, data, err, func() error {
			var want Control
			wantErr := json.Unmarshal(data, &want)
			if err == nil && wantErr == nil && got != want {
				t.Fatalf("DecodeControl = %#v, stdlib = %#v", got, want)
			}
			return wantErr
		})
	})
}

func FuzzReadHello(f *testing.F) {
	seedStream(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		assertStreamBounded(t, data, func(c *Conn) error {
			_, err := c.ReadHello()
			return err
		})
		if len(data) > MaxFrameSize {
			return
		}
		got, err := readConn(bytes.NewReader(data)).ReadHello()
		var want Hello
		wantErr := json.NewDecoder(bytes.NewReader(data)).Decode(&want)
		assertStreamAgree(t, data, err, wantErr, err == nil && wantErr == nil && got != want)
	})
}

func FuzzReadWelcome(f *testing.F) {
	seedStream(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		assertStreamBounded(t, data, func(c *Conn) error {
			_, err := c.ReadWelcome()
			return err
		})
		if len(data) > MaxFrameSize {
			return
		}
		got, err := readConn(bytes.NewReader(data)).ReadWelcome()
		var want Welcome
		wantErr := json.NewDecoder(bytes.NewReader(data)).Decode(&want)
		assertStreamAgree(t, data, err, wantErr, err == nil && wantErr == nil && got != want)
	})
}

func FuzzReadControl(f *testing.F) {
	seedStream(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		assertStreamBounded(t, data, func(c *Conn) error {
			_, err := c.ReadControl()
			return err
		})
		if len(data) > MaxFrameSize {
			return
		}
		got, err := readConn(bytes.NewReader(data)).ReadControl()
		var want Control
		wantErr := json.NewDecoder(bytes.NewReader(data)).Decode(&want)
		assertStreamAgree(t, data, err, wantErr, err == nil && wantErr == nil && got != want)
	})
}

func FuzzReadValue(f *testing.F) {
	seedStream(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		assertStreamBounded(t, data, func(c *Conn) error {
			_, err := c.readValue()
			return err
		})
		if len(data) > MaxFrameSize {
			return
		}
		ours := readConn(bytes.NewReader(data))
		std := json.NewDecoder(bytes.NewReader(data))
		for range 3 {
			raw, err := ours.readValue()
			var want json.RawMessage
			wantErr := std.Decode(&want)
			if len(data) <= MaxFrameSize && errors.Is(err, ErrFrameTooLarge) {
				t.Fatalf("false oversize for %q", data)
			}
			if errors.Is(err, ErrFrameTooLarge) {
				return
			}
			if (err == nil) != (wantErr == nil) {
				t.Fatalf("readValue err=%v std=%v data=%q", err, wantErr, data)
			}
			if err != nil {
				return
			}
			if !bytes.Equal(raw, want) {
				t.Fatalf("value %q, stdlib %q", raw, want)
			}
		}
	})
}

func seedDecode(f *testing.F) {
	f.Helper()
	f.Add([]byte(`{"version":1,"token":"abc","domain":"demo","mode":"http"}`))
	f.Add([]byte(`{"version":1,"token":"a\"{b[c]d}","mode":"http"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{`))
	f.Add([]byte(`{"version":1,}`))
	f.Add([]byte(`{"version":"nope"}`))
	f.Add([]byte(`{"version":1}{"version":2}`))
	f.Add([]byte(" \r\n\t"))
	f.Add([]byte(nestedHello(MaxDepth + 1)))
	f.Add(bytes.Repeat([]byte("["), MaxDepth+1))
	f.Add([]byte{0xff, 0xfe, '{'})
}

func seedStream(f *testing.F) {
	f.Helper()
	seedDecode(f)
	f.Add([]byte("{\"version\":1,\"token\":\"abc\",\"mode\":\"http\"}\n{\"type\":\"ping\"}\n"))
	f.Add([]byte("{\"ok\":true,\"domain\":\"demo\",\"url\":\"https://demo.tunnl.test\"}\n"))
	var pretty bytes.Buffer
	enc := json.NewEncoder(&pretty)
	enc.SetIndent("", "  ")
	_ = enc.Encode(Hello{Version: 1, Token: "abc", Mode: "http"})
	f.Add(pretty.Bytes())
}

func assertDecoded(t *testing.T, data []byte, err error, std func() error) {
	t.Helper()
	if len(data) > MaxFrameSize {
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("oversized input (%d) error = %v", len(data), err)
		}
		return
	}
	if errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("false oversize for %d bytes", len(data))
	}
	if errors.Is(err, ErrMessageTooDeep) {
		depth, depthErr := firstValueDepth(data)
		if depthErr != nil || depth > MaxDepth {
			return
		}
		t.Fatalf("rejected depth %d: %q", depth, data)
	}
	wantErr := std()
	if (err == nil) != (wantErr == nil) {
		t.Fatalf("err=%v std=%v data=%q", err, wantErr, data)
	}
}

func assertStreamBounded(t *testing.T, data []byte, read func(*Conn) error) {
	t.Helper()
	counter := &countReader{b: data}
	_ = read(NewConn(counter))
	if counter.n > MaxFrameSize+1 {
		t.Fatalf("read %d bytes from %d input, budget %d", counter.n, len(data), MaxFrameSize+1)
	}
}

func assertStreamAgree(t *testing.T, data []byte, err, wantErr error, mismatch bool) {
	t.Helper()
	if errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("false oversize for %d bytes: %q", len(data), data)
	}
	if errors.Is(err, ErrMessageTooDeep) {
		depth, depthErr := firstValueDepth(data)
		if depthErr != nil || depth > MaxDepth {
			return
		}
		t.Fatalf("rejected depth %d: %q", depth, data)
	}
	if (err == nil) != (wantErr == nil) || mismatch {
		t.Fatalf("err=%v std=%v data=%q", err, wantErr, data)
	}
}

func firstValueDepth(data []byte) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	maxDepth := 0
	depth := 0
	started := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return maxDepth, err
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				started = true
				if depth > maxDepth {
					maxDepth = depth
				}
			case '}', ']':
				depth--
			}
		} else {
			started = true
		}
		if started && depth == 0 {
			return maxDepth, nil
		}
	}
}

type countReader struct {
	b []byte
	n int
}

func (r *countReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	r.n += n
	return n, nil
}

func (r *countReader) Write(p []byte) (int, error) { return len(p), nil }
