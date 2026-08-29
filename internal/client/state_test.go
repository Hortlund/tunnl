package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestConcurrentStateWritesDoNotLoseDomains(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	const count = 32
	var group sync.WaitGroup
	for index := range count {
		group.Add(1)
		go func() {
			defer group.Done()
			key := "relay|target-" + strconv.Itoa(index)
			if err := saveDomainAt(root, key, "domain-"+strconv.Itoa(index)); err != nil {
				t.Errorf("saveDomainAt(%q): %v", key, err)
			}
		}()
	}
	group.Wait()
	for index := range count {
		key := "relay|target-" + strconv.Itoa(index)
		want := "domain-" + strconv.Itoa(index)
		if got := loadDomainAt(root, key); got != want {
			t.Errorf("loadDomainAt(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestLegacyStateIsStillReadable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	data, err := json.Marshal(legacyState{Domains: map[string]string{"relay|target": "legacy-domain"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "state.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := loadDomainAt(root, "relay|target"); got != "legacy-domain" {
		t.Fatalf("legacy domain = %q", got)
	}
}
