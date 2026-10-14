package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Hortlund/tunnl/internal/client"
	"github.com/Hortlund/tunnl/internal/protocol"
	"github.com/Hortlund/tunnl/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tunnl:", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	mode := "http"
	if len(args) > 0 && (args[0] == "http" || args[0] == "tcp") {
		mode = args[0]
		args = args[1:]
	}
	flags := flag.NewFlagSet("tunnl", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	port := flags.Int("port", 0, "local port to expose")
	targetValue := flags.String("to", "", "local HTTP URL, or host:port in tcp mode")
	domain := flags.String("domain", "", "requested tunnl subdomain")
	server := flags.String("server", envOr("TUNNL_SERVER", "relay.tunnl.at:443"), "tunnl relay address")
	token := flags.String("token", os.Getenv("TUNNL_TOKEN"), "authentication token (or TUNNL_TOKEN)")
	hostHeader := flags.String("host-header", "", "Host header sent to the local service")
	insecure := flags.Bool("insecure", false, "allow an untrusted relay certificate (development only)")
	responseHeaderTimeout := flags.Duration("response-header-timeout", envDuration("TUNNL_RESPONSE_HEADER_TIMEOUT", 0), "maximum wait for local response headers (0 disables)")
	quicTimeout := flags.Duration("quic-timeout", envDuration("TUNNL_QUIC_TIMEOUT", 0), "how long to wait for QUIC before trying websocket (0 uses 5s)")
	websocketOnly := flags.Bool("websocket-only", false, "use the websocket fallback and skip QUIC")
	noWebsocket := flags.Bool("no-websocket", false, "do not fall back to websocket when QUIC fails")
	logFormat := flags.String("log-format", envOr("TUNNL_LOG_FORMAT", "text"), "client log format: text or json")
	logLevel := flags.String("log-level", envOr("TUNNL_LOG_LEVEL", "info"), "client log level: debug, info, warn, or error")
	showVersion := flags.Bool("version", false, "print version information")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("tunnl %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return nil
	}
	if *token == "" {
		return errors.New("an authentication token is required; set TUNNL_TOKEN or use --token")
	}
	if *websocketOnly && *noWebsocket {
		return errors.New("--websocket-only and --no-websocket cannot be used together")
	}
	var target *url.URL
	tcpAddress := ""
	if mode == "tcp" {
		if *domain != "" || *hostHeader != "" {
			return errors.New("tcp mode does not use --domain or --host-header")
		}
		if *targetValue == "" {
			if *port < 1 || *port > 65535 {
				return errors.New("use --port with a valid local port, or provide --to host:port")
			}
			tcpAddress = net.JoinHostPort("127.0.0.1", strconv.Itoa(*port))
		} else if *port != 0 {
			return errors.New("--port and --to cannot be used together")
		} else {
			if _, _, err := net.SplitHostPort(*targetValue); err != nil {
				return errors.New("--to must be host:port for tcp mode")
			}
			tcpAddress = *targetValue
		}
	} else {
		if *targetValue == "" {
			if *port < 1 || *port > 65535 {
				return errors.New("use --port with a valid local port, or provide --to")
			}
			*targetValue = "http://127.0.0.1:" + strconv.Itoa(*port)
		} else if *port != 0 {
			return errors.New("--port and --to cannot be used together")
		}
		parsed, err := url.Parse(*targetValue)
		if err != nil || parsed.Host == "" {
			return errors.New("--to must be a complete HTTP URL")
		}
		target = parsed
	}

	level, err := parseLogLevel(*logLevel)
	if err != nil {
		return err
	}
	var handler slog.Handler
	switch strings.ToLower(*logFormat) {
	case "", "text":
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	default:
		return fmt.Errorf("unknown log format %q", *logFormat)
	}
	logger := slog.New(handler)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	delay := time.Second
	localTarget := tcpAddress
	if target != nil {
		localTarget = target.String()
	}
	config := client.Config{
		Server:                *server,
		Token:                 *token,
		Domain:                *domain,
		Target:                target,
		HostHeader:            *hostHeader,
		InsecureSkipVerify:    *insecure,
		ResponseHeaderTimeout: *responseHeaderTimeout,
		Logger:                logger,
		Mode:                  mode,
		TCPAddress:            tcpAddress,
		QUICDialTimeout:       *quicTimeout,
		WebSocketOnly:         *websocketOnly,
		DisableWebSocket:      *noWebsocket,
		OnReady: func(welcome protocol.Welcome) {
			delay = time.Second
			fmt.Printf("\n  tunnl connected\n  public: %s\n  target: %s\n\n", welcome.URL, localTarget)
		},
	}

	for {
		tunnel, err := client.New(config)
		if err != nil {
			return err
		}
		err = tunnel.Run(ctx)
		if ctx.Err() != nil || err == nil {
			return nil
		}
		if strings.Contains(err.Error(), "relay rejected tunnel") {
			return err
		}
		jitter := time.Duration(rand.IntN(500)) * time.Millisecond
		logger.Warn("tunnel disconnected; reconnecting", "error", err, "retry_in", (delay + jitter).String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay + jitter):
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return fallback
}
