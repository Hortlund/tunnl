package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const managedComment = "Managed by tunnl"

type Cloudflare struct {
	token   string
	baseURL string
	client  *http.Client
}

func NewCloudflare(token string) *Cloudflare {
	return &Cloudflare{token: token, baseURL: "https://api.cloudflare.com/client/v4", client: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Cloudflare) Reconcile(ctx context.Context, zone, baseDomain, target string) error {
	if c.token == "" {
		return errors.New("TUNNL_CLOUDFLARE_API_TOKEN is not configured")
	}
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	baseDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(baseDomain)), ".")
	if zone == "" || (baseDomain != zone && !strings.HasSuffix(baseDomain, "."+zone)) {
		return errors.New("DNS zone must contain the configured base domain")
	}
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		return errors.New("DNS target must be a valid IPv4 or IPv6 address")
	}
	recordType := "AAAA"
	if ip.To4() != nil {
		recordType = "A"
		target = ip.To4().String()
	} else {
		target = ip.String()
	}
	zoneID, err := c.zoneID(ctx, zone)
	if err != nil {
		return err
	}
	for _, record := range []struct {
		name    string
		proxied bool
	}{{name: "*." + baseDomain, proxied: true}, {name: "relay." + baseDomain, proxied: false}} {
		if err := c.upsertRecord(ctx, zoneID, recordType, record.name, target, record.proxied); err != nil {
			return err
		}
	}
	return nil
}

type envelope[T any] struct {
	Success bool `json:"success"`
	Result  T    `json:"result"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (c *Cloudflare) zoneID(ctx context.Context, zone string) (string, error) {
	var response envelope[[]struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}]
	if err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(zone), nil, &response); err != nil {
		return "", err
	}
	if len(response.Result) != 1 || !strings.EqualFold(response.Result[0].Name, zone) {
		return "", fmt.Errorf("Cloudflare zone %q was not found uniquely", zone)
	}
	return response.Result[0].ID, nil
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Comment string `json:"comment"`
}

func (c *Cloudflare) upsertRecord(ctx context.Context, zoneID, recordType, name, target string, proxied bool) error {
	query := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", url.PathEscape(zoneID), url.QueryEscape(recordType), url.QueryEscape(name))
	var listed envelope[[]dnsRecord]
	if err := c.do(ctx, http.MethodGet, query, nil, &listed); err != nil {
		return err
	}
	if len(listed.Result) > 1 {
		return fmt.Errorf("multiple %s records already exist for %s", recordType, name)
	}
	body := map[string]any{"type": recordType, "name": name, "content": target, "ttl": 1, "proxied": proxied, "comment": managedComment}
	method := http.MethodPost
	path := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	if len(listed.Result) == 1 {
		existing := listed.Result[0]
		if existing.Comment != managedComment {
			return fmt.Errorf("refusing to overwrite unmanaged DNS record %s", name)
		}
		method = http.MethodPut
		path += "/" + url.PathEscape(existing.ID)
	}
	var updated envelope[dnsRecord]
	if err := c.do(ctx, method, path, body, &updated); err != nil {
		return fmt.Errorf("reconcile %s: %w", name, err)
	}
	return nil
}

func (c *Cloudflare) do(ctx context.Context, method, path string, body, destination any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Cloudflare API returned %s", response.Status)
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return fmt.Errorf("decode Cloudflare response: %w", err)
	}
	var status envelope[json.RawMessage]
	if err := json.Unmarshal(data, &status); err == nil && !status.Success {
		if len(status.Errors) > 0 && status.Errors[0].Message != "" {
			return errors.New(status.Errors[0].Message)
		}
		return errors.New("Cloudflare API operation failed")
	}
	return nil
}
