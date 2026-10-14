package mux

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

type memPipe struct {
	in  <-chan []byte
	out chan<- []byte
}

func (m memPipe) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case message, ok := <-m.in:
		if !ok {
			return nil, io.EOF
		}
		return message, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m memPipe) WriteMessage(ctx context.Context, message []byte) error {
	copied := append([]byte(nil), message...)
	select {
	case m.out <- copied:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m memPipe) Close() error { return nil }

func TestMuxRoundTrip(t *testing.T) {
	t.Parallel()
	clientToServer := make(chan []byte, 8)
	serverToClient := make(chan []byte, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := New(ctx, Client, memPipe{in: serverToClient, out: clientToServer}, "client")
	server := New(ctx, Server, memPipe{in: clientToServer, out: serverToClient}, "server")

	control, err := client.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := accepted.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("control read = %q %v", buf[:n], err)
	}

	data, err := server.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Write([]byte("proxied")); err != nil {
		t.Fatal(err)
	}
	incoming, err := client.AcceptStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n, err = incoming.Read(buf)
	if err != nil || string(buf[:n]) != "proxied" {
		t.Fatalf("data read = %q %v", buf[:n], err)
	}
	if err := data.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := incoming.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("close = %v, want EOF", err)
	}
}

func TestMuxReadDeadline(t *testing.T) {
	t.Parallel()
	clientToServer := make(chan []byte, 4)
	serverToClient := make(chan []byte, 4)
	ctx := context.Background()
	client := New(ctx, Client, memPipe{in: serverToClient, out: clientToServer}, "client")
	_ = New(ctx, Server, memPipe{in: clientToServer, out: serverToClient}, "server")
	control, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = control.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("read succeeded after the deadline")
	}
}
