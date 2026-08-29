package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
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
	if len(args) > 0 && args[0] == "http" {
		args = args[1:]
	}
	flags := flag.NewFlagSet("tunnl", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	port := flags.Int("port", 0, "local HTTP port to expose")
	targetValue := flags.String("to", "", "local HTTP URL to forward to")
	domain := flags.String("domain", "", "requested tunnl subdomain")
	server := flags.String("server", envOr("TUNNL_SERVER", "relay.tunnl.at:443"), "tunnl relay address")
	token := flags.String("token", os.Getenv("TUNNL_TOKEN"), "authentication token (or TUNNL_TOKEN)")
	hostHeader := flags.String("host-header", "", "Host header sent to the local service")
	insecure := flags.Bool("insecure", false, "allow an untrusted relay certificate (development only)")
	responseHeaderTimeout := flags.Duration("response-header-timeout", envDuration("TUNNL_RESPONSE_HEADER_TIMEOUT", 0), "maximum wait for local response headers (0 disables)")
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
	if *targetValue == "" {
		if *port < 1 || *port > 65535 {
			return errors.New("use --port with a valid local port, or provide --to")
		}
		*targetValue = "http://127.0.0.1:" + strconv.Itoa(*port)
	} else if *port != 0 {
		return errors.New("--port and --to cannot be used together")
	}
	target, err := url.Parse(*targetValue)
	if err != nil || target.Host == "" {
		return errors.New("--to must be a complete HTTP URL")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	delay := time.Second
	config := client.Config{
		Server:                *server,
		Token:                 *token,
		Domain:                *domain,
		Target:                target,
		HostHeader:            *hostHeader,
		InsecureSkipVerify:    *insecure,
		ResponseHeaderTimeout: *responseHeaderTimeout,
		Logger:                logger,
		OnReady: func(welcome protocol.Welcome) {
			delay = time.Second
			fmt.Printf("\n  tunnl connected\n  public: %s\n  target: %s\n\n", welcome.URL, target)
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
		logger.Warn("tunnel disconnected; reconnecting", "error", err, "in", delay+jitter)
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
