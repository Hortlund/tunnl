package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type legacyState struct {
	Domains map[string]string `json:"domains"`
}

type domainState struct {
	Key    string `json:"key"`
	Domain string `json:"domain"`
}

func stateRoot() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tunnl"), nil
}

func stateFilename(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:]) + ".json"
}

func loadDomain(key string) string {
	root, err := stateRoot()
	if err != nil {
		return ""
	}
	return loadDomainAt(root, key)
}

func loadDomainAt(root, key string) string {
	data, err := os.ReadFile(filepath.Join(root, "domains", stateFilename(key)))
	if err == nil {
		var saved domainState
		if json.Unmarshal(data, &saved) == nil && saved.Key == key {
			return saved.Domain
		}
	}

	data, err = os.ReadFile(filepath.Join(root, "state.json"))
	if err != nil {
		return ""
	}
	var saved legacyState
	if json.Unmarshal(data, &saved) != nil {
		return ""
	}
	return saved.Domains[key]
}

func saveDomain(key, domain string) error {
	root, err := stateRoot()
	if err != nil {
		return err
	}
	return saveDomainAt(root, key, domain)
}

func saveDomainAt(root, key, domain string) error {
	directory := filepath.Join(root, "domains")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(domainState{Key: key, Domain: domain}, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "state-*.json")
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
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	destination := filepath.Join(directory, stateFilename(key))
	if err := os.Rename(temporaryName, destination); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return os.Rename(temporaryName, destination)
	}
	return nil
}
