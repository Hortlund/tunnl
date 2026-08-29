package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestCloudflareReconcileCreatesManagedRecords(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var created []map[string]any
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/zones":
			writeCloudflareJSON(writer, map[string]any{"success": true, "result": []map[string]string{{"id": "zone-id", "name": "tunnl.at"}}})
		case request.Method == http.MethodGet && request.URL.Path == "/zones/zone-id/dns_records":
			writeCloudflareJSON(writer, map[string]any{"success": true, "result": []any{}})
		case request.Method == http.MethodPost && request.URL.Path == "/zones/zone-id/dns_records":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			created = append(created, body)
			mu.Unlock()
			body["id"] = "record-id"
			writeCloudflareJSON(writer, map[string]any{"success": true, "result": body})
		default:
			http.Error(writer, "unexpected request", http.StatusNotFound)
		}
	}))
	defer api.Close()
	provider := NewCloudflare("secret")
	provider.baseURL = api.URL
	provider.client = api.Client()
	if err := provider.Reconcile(context.Background(), "tunnl.at", "tunnl.at", "203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	if len(created) != 2 {
		t.Fatalf("created %d records, want 2", len(created))
	}
	names := []string{created[0]["name"].(string), created[1]["name"].(string)}
	sort.Strings(names)
	if strings.Join(names, ",") != "*.tunnl.at,relay.tunnl.at" {
		t.Fatalf("record names = %v", names)
	}
	for _, record := range created {
		if record["content"] != "203.0.113.10" || record["type"] != "A" || record["comment"] != managedComment {
			t.Fatalf("record = %#v", record)
		}
	}
}

func TestCloudflareReconcileRefusesUnmanagedRecord(t *testing.T) {
	t.Parallel()
	api := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/zones":
			writeCloudflareJSON(writer, map[string]any{"success": true, "result": []map[string]string{{"id": "zone-id", "name": "tunnl.at"}}})
		case "/zones/zone-id/dns_records":
			writeCloudflareJSON(writer, map[string]any{"success": true, "result": []map[string]string{{"id": "existing", "name": "*.tunnl.at", "type": "A", "comment": "managed elsewhere"}}})
		default:
			http.Error(writer, "unexpected request", http.StatusNotFound)
		}
	}))
	defer api.Close()
	provider := NewCloudflare("secret")
	provider.baseURL = api.URL
	provider.client = api.Client()
	err := provider.Reconcile(context.Background(), "tunnl.at", "tunnl.at", "203.0.113.10")
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite unmanaged") {
		t.Fatalf("Reconcile() error = %v", err)
	}
}

func writeCloudflareJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
