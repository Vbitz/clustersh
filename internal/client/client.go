// Package client implements the frontend client library.
package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"j5.nz/clustersh/internal/protocol"
	"j5.nz/clustersh/internal/security"
	"j5.nz/clustersh/internal/storage"
)

// Client is the API client for the coordinator.
type Client struct {
	config    *storage.ClientConfig
	configDir string
	keyPair   *security.KeyPair
	caCert    []byte
	http      *http.Client
}

// New creates a new client.
func New(config *storage.ClientConfig, configDir string) (*Client, error) {
	c := &Client{
		config:    config,
		configDir: configDir,
		http:      &http.Client{Timeout: 30 * time.Second},
	}

	// Try to load existing keypair and certificate
	keyPath := filepath.Join(configDir, "client.key")
	certPath := filepath.Join(configDir, "client.crt")
	caPath := filepath.Join(configDir, "ca.crt")

	if _, err := os.Stat(keyPath); err == nil {
		kp, err := security.LoadKeyPairFromFiles(keyPath, certPath)
		if err == nil {
			c.keyPair = kp
		}
	}

	if data, err := os.ReadFile(caPath); err == nil {
		c.caCert = data
	}

	// Set up TLS if we have credentials
	if c.keyPair != nil && len(c.keyPair.CertPEM) > 0 && len(c.caCert) > 0 {
		tlsConfig, err := security.NewClientTLSConfig(c.caCert, c.keyPair)
		if err == nil {
			c.http.Transport = &http.Transport{TLSClientConfig: tlsConfig}
		}
	} else {
		// Allow insecure for initial setup
		c.http.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return c, nil
}

// Machines returns the list of connected machines.
func (c *Client) Machines() ([]protocol.Machine, error) {
	resp, err := c.get("/machines")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var machines []protocol.Machine
	if err := json.NewDecoder(resp.Body).Decode(&machines); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return machines, nil
}

// Run executes a command on a machine.
func (c *Client) Run(machine, command string, files []protocol.File, timeout time.Duration) (string, error) {
	req := protocol.RunRequest{
		Machine: machine,
		Command: command,
		Files:   files,
		Timeout: protocol.Duration(timeout),
	}

	resp, err := c.post("/run", req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result protocol.RunResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return result.JobID, nil
}

// Output retrieves job output.
func (c *Client) Output(jobID string) (*protocol.JobOutput, error) {
	resp, err := c.get("/output/" + jobID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var output protocol.JobOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &output, nil
}

// History retrieves command history for a machine.
func (c *Client) History(machine string) ([]protocol.HistoryEntry, error) {
	resp, err := c.get("/history/" + machine)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var history []protocol.HistoryEntry
	if err := json.NewDecoder(resp.Body).Decode(&history); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return history, nil
}

// Cancel cancels a running command.
func (c *Client) Cancel(jobID string) error {
	resp, err := c.post("/cancel/"+jobID, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Login requests access to the coordinator.
func (c *Client) Login(coordinatorURL string) (string, error) {
	c.config.CoordinatorURL = coordinatorURL

	// Generate new keypair if needed
	if c.keyPair == nil {
		kp, err := security.GenerateKeyPair()
		if err != nil {
			return "", fmt.Errorf("generate keypair: %w", err)
		}
		c.keyPair = kp

		keyPath := filepath.Join(c.configDir, "client.key")
		if err := c.keyPair.SaveToFiles(keyPath, ""); err != nil {
			return "", fmt.Errorf("save keypair: %w", err)
		}
	}

	// Download CA cert
	resp, err := c.http.Get(coordinatorURL + "/ca.crt")
	if err != nil {
		return "", fmt.Errorf("download CA cert: %w", err)
	}
	defer resp.Body.Close()

	c.caCert, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read CA cert: %w", err)
	}

	caPath := filepath.Join(c.configDir, "ca.crt")
	if err := os.WriteFile(caPath, c.caCert, 0644); err != nil {
		return "", fmt.Errorf("save CA cert: %w", err)
	}

	// Create login request
	pubKeyPEM, err := c.keyPair.PublicKeyPEM()
	if err != nil {
		return "", fmt.Errorf("get public key: %w", err)
	}

	fingerprint := c.keyPair.Fingerprint()
	timestamp := time.Now().Unix()

	// Sign the timestamp
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))
	r, s, err := ecdsa.Sign(rand.Reader, c.keyPair.PrivateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	// Encode signature as r || s (32 bytes each for P-256)
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	signature := base64.StdEncoding.EncodeToString(sigBytes)

	loginReq := protocol.LoginRequest{
		PublicKey:   string(pubKeyPEM),
		Fingerprint: fingerprint,
		Signature:   signature,
		Timestamp:   timestamp,
	}

	body, err := json.Marshal(loginReq)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	resp, err = c.http.Post(coordinatorURL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	var loginResp protocol.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	if loginResp.Status == "approved" {
		// Save certificate
		certPath := filepath.Join(c.configDir, "client.crt")
		if err := os.WriteFile(certPath, []byte(loginResp.Certificate), 0644); err != nil {
			return "", fmt.Errorf("save certificate: %w", err)
		}
		if err := c.keyPair.SetCertificate([]byte(loginResp.Certificate)); err != nil {
			return "", fmt.Errorf("set certificate: %w", err)
		}

		// Update HTTP client with TLS
		tlsConfig, err := security.NewClientTLSConfig(c.caCert, c.keyPair)
		if err != nil {
			return "", fmt.Errorf("create TLS config: %w", err)
		}
		c.http.Transport = &http.Transport{TLSClientConfig: tlsConfig}

		// Save config
		configPath := filepath.Join(c.configDir, "config.json")
		if err := storage.SaveJSON(configPath, c.config); err != nil {
			return "", fmt.Errorf("save config: %w", err)
		}

		return "", nil
	}

	return fingerprint, nil
}

// WaitForApproval polls for approval and downloads the certificate.
func (c *Client) WaitForApproval(fingerprint string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		cert, err := c.checkApproval()
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		if cert != "" {
			certPath := filepath.Join(c.configDir, "client.crt")
			if err := os.WriteFile(certPath, []byte(cert), 0644); err != nil {
				return fmt.Errorf("save certificate: %w", err)
			}
			if err := c.keyPair.SetCertificate([]byte(cert)); err != nil {
				return fmt.Errorf("set certificate: %w", err)
			}

			tlsConfig, err := security.NewClientTLSConfig(c.caCert, c.keyPair)
			if err != nil {
				return fmt.Errorf("create TLS config: %w", err)
			}
			c.http.Transport = &http.Transport{TLSClientConfig: tlsConfig}

			configPath := filepath.Join(c.configDir, "config.json")
			if err := storage.SaveJSON(configPath, c.config); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			return nil
		}

		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("approval timeout")
}

func (c *Client) checkApproval() (string, error) {
	pubKeyPEM, _ := c.keyPair.PublicKeyPEM()
	fingerprint := c.keyPair.Fingerprint()
	timestamp := time.Now().Unix()

	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))
	r, s, _ := ecdsa.Sign(rand.Reader, c.keyPair.PrivateKey, hash[:])

	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	signature := base64.StdEncoding.EncodeToString(sigBytes)

	loginReq := protocol.LoginRequest{
		PublicKey:   string(pubKeyPEM),
		Fingerprint: fingerprint,
		Signature:   signature,
		Timestamp:   timestamp,
	}

	body, _ := json.Marshal(loginReq)
	resp, err := c.http.Post(c.config.CoordinatorURL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var loginResp protocol.LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return "", err
	}

	if loginResp.Status == "approved" {
		return loginResp.Certificate, nil
	}

	return "", nil
}

func (c *Client) get(path string) (*http.Response, error) {
	if c.config.CoordinatorURL == "" {
		return nil, fmt.Errorf("coordinator URL not configured. Run 'clustersh login <url>' first")
	}
	url := c.config.CoordinatorURL + path
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var apiErr protocol.APIError
		if json.Unmarshal(body, &apiErr) == nil {
			return nil, fmt.Errorf("%s", apiErr.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}

func (c *Client) post(path string, body interface{}) (*http.Response, error) {
	if c.config.CoordinatorURL == "" {
		return nil, fmt.Errorf("coordinator URL not configured. Run 'clustersh login <url>' first")
	}
	url := c.config.CoordinatorURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	resp, err := c.http.Post(url, "application/json", bodyReader)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var apiErr protocol.APIError
		if json.Unmarshal(body, &apiErr) == nil {
			return nil, fmt.Errorf("%s", apiErr.Error)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}

// LoadPublicKey loads a public key from a PEM file for signature verification.
func LoadPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return security.ParsePublicKeyPEM(data)
}

// VerifySignature verifies a signature against data using a public key.
func VerifySignature(pubKey *ecdsa.PublicKey, data, signature []byte) bool {
	hash := sha256.Sum256(data)

	if len(signature) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return ecdsa.Verify(pubKey, hash[:], r, s)
}
