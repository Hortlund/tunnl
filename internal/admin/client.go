package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("admin URL must be a complete HTTP or HTTPS URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("admin URL must use HTTP or HTTPS")
	}
	if token == "" {
		return nil, errors.New("admin token is required")
	}
	return &Client{baseURL: parsed.String(), token: token, http: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (c *Client) Status(ctx context.Context) (Status, error) {
	var result Status
	err := c.do(ctx, http.MethodGet, "/api/v1/status", nil, &result)
	return result, err
}

func (c *Client) Metrics(ctx context.Context) (Metrics, error) {
	var result Metrics
	err := c.do(ctx, http.MethodGet, "/api/v1/metrics", nil, &result)
	return result, err
}

func (c *Client) Tokens(ctx context.Context) ([]Token, error) {
	var result []Token
	err := c.do(ctx, http.MethodGet, "/api/v1/tokens", nil, &result)
	return result, err
}

func (c *Client) CreateToken(ctx context.Context, label string) (CreatedToken, error) {
	var result CreatedToken
	err := c.do(ctx, http.MethodPost, "/api/v1/tokens", CreateTokenRequest{Label: label}, &result)
	return result, err
}

func (c *Client) RevokeToken(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/tokens/"+url.PathEscape(id), nil, nil)
}

func (c *Client) DNS(ctx context.Context) (DNSConfig, error) {
	var result DNSConfig
	err := c.do(ctx, http.MethodGet, "/api/v1/dns", nil, &result)
	return result, err
}

func (c *Client) SetDNS(ctx context.Context, config DNSConfig) (DNSConfig, error) {
	var result DNSConfig
	err := c.do(ctx, http.MethodPut, "/api/v1/dns", config, &result)
	return result, err
}

func (c *Client) ReconcileDNS(ctx context.Context) (OperationResult, error) {
	var result OperationResult
	err := c.do(ctx, http.MethodPost, "/api/v1/dns/reconcile", struct{}{}, &result)
	return result, err
}

func (c *Client) do(ctx context.Context, method, path string, body, result any) error {
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
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		return fmt.Errorf("admin API returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	if result == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(result); err != nil {
		return fmt.Errorf("decode admin response: %w", err)
	}
	return nil
}
