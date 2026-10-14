package wsock

import (
	"bufio"
	"io"
	"net"
	"testing"
)

func TestWebSocketBinaryRoundTrip(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		request, err := readRequestLine(reader)
		if err != nil {
			errCh <- err
			return
		}
		key := request["Sec-WebSocket-Key"]
		server, err := Accept(serverConn, reader, serverConn, key)
		if err != nil {
			errCh <- err
			return
		}
		message, err := server.ReadMessage()
		if err != nil {
			errCh <- err
			return
		}
		errCh <- server.WriteMessage(append([]byte("echo:"), message...))
	}()

	client, err := Client(clientConn, "relay.example.com", "/_tunnl/ws")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	message, err := client.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(message) != "echo:ping" {
		t.Fatalf("message = %q", message)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func readRequestLine(reader *bufio.Reader) (map[string]string, error) {
	headers := make(map[string]string)
	if _, err := reader.ReadString('\n'); err != nil {
		return nil, err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = line[:len(line)-1]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if line == "" {
			return headers, nil
		}
		name, value, ok := splitHeader(line)
		if !ok {
			return nil, io.ErrUnexpectedEOF
		}
		headers[name] = value
	}
}

func splitHeader(line string) (string, string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] == ':' {
			return line[:i], trim(line[i+1:]), true
		}
	}
	return "", "", false
}

func trim(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t') {
		value = value[1:]
	}
	return value
}
