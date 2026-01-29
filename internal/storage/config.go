// Package storage handles JSON file storage for configuration and job data.
package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CoordinatorConfig holds coordinator configuration.
type CoordinatorConfig struct {
	ListenAddr string `json:"listen_addr"`
	Port       int    `json:"port"`
}

// DefaultCoordinatorConfig returns sensible defaults.
func DefaultCoordinatorConfig() *CoordinatorConfig {
	return &CoordinatorConfig{
		ListenAddr: "0.0.0.0",
		Port:       5672,
	}
}

// AgentConfig holds agent configuration.
type AgentConfig struct {
	CoordinatorURL string `json:"coordinator_url"`
	MachineName    string `json:"machine_name"`
}

// ClientConfig holds CLI client configuration.
type ClientConfig struct {
	CoordinatorURL string        `json:"coordinator_url"`
	DefaultTimeout time.Duration `json:"default_timeout"`
}

// DefaultClientConfig returns sensible defaults.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		DefaultTimeout: 5 * time.Minute,
	}
}

// ApprovedClient represents an approved client.
type ApprovedClient struct {
	Fingerprint string    `json:"fingerprint"`
	Name        string    `json:"name"`
	ApprovedAt  time.Time `json:"approved_at"`
}

// ApprovedClients holds the list of approved clients.
type ApprovedClients struct {
	Clients []ApprovedClient `json:"clients"`
}

// PendingLogin represents a pending login request.
type PendingLogin struct {
	Fingerprint string    `json:"fingerprint"`
	PublicKey   string    `json:"public_key"`
	RequestedAt time.Time `json:"requested_at"`
}

// PendingLogins holds the list of pending login requests.
type PendingLogins struct {
	Logins []PendingLogin `json:"logins"`
}

// LoadJSON loads a JSON file into the given struct.
func LoadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// SaveJSON saves a struct to a JSON file.
func SaveJSON(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// ConfigDir returns the configuration directory for the given component.
func ConfigDir(component string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}
	return filepath.Join(home, ".config", "clustersh", component), nil
}

// EnsureConfigDir creates the configuration directory if it doesn't exist.
func EnsureConfigDir(component string) (string, error) {
	dir, err := ConfigDir(component)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config directory: %w", err)
	}
	return dir, nil
}
