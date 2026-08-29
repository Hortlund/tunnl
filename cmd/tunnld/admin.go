package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Hortlund/tunnl/internal/admin"
)

func runAdmin(args []string) error {
	flags := flag.NewFlagSet("tunnld admin", flag.ContinueOnError)
	adminURL := flags.String("url", envOr("TUNNL_ADMIN_URL", "http://127.0.0.1:9090"), "admin API URL")
	adminToken := flags.String("token", os.Getenv("TUNNL_ADMIN_TOKEN"), "admin API token")
	jsonOutput := flags.Bool("json", false, "print JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	command := flags.Args()
	if len(command) == 0 {
		return errors.New("admin command required: status, tokens, or dns")
	}
	client, err := admin.NewClient(*adminURL, *adminToken)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch command[0] {
	case "status":
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(status)
		}
		fmt.Printf("tunnld %s\nstatus: operational\nuptime: %s\nactive tunnels: %d\nreservations: %d\nrequests: %d (%d failed)\n", status.Version, time.Duration(status.UptimeSeconds)*time.Second, status.ActiveTunnels, status.Reservations, status.TotalRequests, status.FailedRequests)
		for _, tunnel := range status.Tunnels {
			fmt.Printf("  %s.%s  %s  connected %s\n", tunnel.Domain, status.BaseDomain, tunnel.Remote, tunnel.ConnectedAt.Local().Format(time.RFC3339))
		}
		return nil
	case "tokens":
		return runAdminTokens(ctx, client, command[1:], *jsonOutput)
	case "dns":
		return runAdminDNS(ctx, client, command[1:], *jsonOutput)
	default:
		return fmt.Errorf("unknown admin command %q", command[0])
	}
}

func runAdminTokens(ctx context.Context, client *admin.Client, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return errors.New("token command required: list, create, or revoke")
	}
	switch args[0] {
	case "list":
		values, err := client.Tokens(ctx)
		if err != nil {
			return err
		}
		if jsonOutput {
			return printJSON(values)
		}
		writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "ID\tLABEL\tPREFIX\tCREATED\tLAST USED")
		for _, value := range values {
			lastUsed := "never"
			if value.LastUsedAt != nil {
				lastUsed = value.LastUsedAt.Local().Format(time.RFC3339)
			}
			fmt.Fprintf(writer, "%s\t%s\t%s…\t%s\t%s\n", value.ID, value.Label, value.Prefix, value.CreatedAt.Local().Format(time.RFC3339), lastUsed)
		}
		return writer.Flush()
	case "create":
		flags := flag.NewFlagSet("tunnld admin tokens create", flag.ContinueOnError)
		label := flags.String("label", "", "human-readable token label")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		created, err := client.CreateToken(ctx, *label)
		if err != nil {
			return err
		}
		if jsonOutput {
			return printJSON(created)
		}
		fmt.Printf("created token %s (%s)\n%s\n\nStore this secret now; it cannot be retrieved again.\n", created.Label, created.ID, created.Secret)
		return nil
	case "revoke":
		flags := flag.NewFlagSet("tunnld admin tokens revoke", flag.ContinueOnError)
		id := flags.String("id", "", "token ID to revoke")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if err := client.RevokeToken(ctx, *id); err != nil {
			return err
		}
		fmt.Println("token revoked")
		return nil
	default:
		return fmt.Errorf("unknown token command %q", args[0])
	}
}

func runAdminDNS(ctx context.Context, client *admin.Client, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return errors.New("DNS command required: show, set, or reconcile")
	}
	switch args[0] {
	case "show":
		config, err := client.DNS(ctx)
		if err != nil {
			return err
		}
		if jsonOutput {
			return printJSON(config)
		}
		fmt.Printf("provider: %s\nzone: %s\ntarget: %s\nCloudflare credential available: %t\n", config.Provider, config.Zone, config.Target, config.CredentialAvailable)
		return nil
	case "set":
		flags := flag.NewFlagSet("tunnld admin dns set", flag.ContinueOnError)
		provider := flags.String("provider", "manual", "DNS provider: manual or cloudflare")
		zone := flags.String("zone", "", "authoritative DNS zone")
		target := flags.String("target", "", "server IPv4 or IPv6 address")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		config, err := client.SetDNS(ctx, admin.DNSConfig{Provider: *provider, Zone: *zone, Target: *target})
		if err != nil {
			return err
		}
		if jsonOutput {
			return printJSON(config)
		}
		fmt.Println("DNS settings saved")
		return nil
	case "reconcile":
		result, err := client.ReconcileDNS(ctx)
		if err != nil {
			return err
		}
		if jsonOutput {
			return printJSON(result)
		}
		fmt.Println(result.Message)
		return nil
	default:
		return fmt.Errorf("unknown DNS command %q", args[0])
	}
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
