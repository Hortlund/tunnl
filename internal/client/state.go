package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type state struct {
	Domains map[string]string `json:"domains"`
}

func statePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tunnl", "state.json"), nil
}

func loadDomain(key string) string {
	path, err := statePath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var saved state
	if json.Unmarshal(data, &saved) != nil {
		return ""
	}
	return saved.Domains[key]
}

func saveDomain(key, domain string) error {
	path, err := statePath()
	if err != nil {
		return err
	}
	saved := state{Domains: make(map[string]string)}
	if data, readErr := os.ReadFile(path); readErr == nil {
		_ = json.Unmarshal(data, &saved)
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if saved.Domains == nil {
		saved.Domains = make(map[string]string)
	}
	saved.Domains[key] = domain
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "state-*.json")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}
