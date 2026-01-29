package coordinator

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"j5.nz/clustersh/internal/security"
	"j5.nz/clustersh/internal/storage"
)

// AuthManager handles client authentication and approval.
type AuthManager struct {
	ca             *security.CA
	configDir      string
	approvedPath   string
	pendingPath    string
	approved       map[string]*storage.ApprovedClient
	pending        map[string]*storage.PendingLogin
	mu             sync.RWMutex
}

// NewAuthManager creates a new auth manager.
func NewAuthManager(ca *security.CA, configDir string) (*AuthManager, error) {
	am := &AuthManager{
		ca:           ca,
		configDir:    configDir,
		approvedPath: filepath.Join(configDir, "approved_clients.json"),
		pendingPath:  filepath.Join(configDir, "pending_logins.json"),
		approved:     make(map[string]*storage.ApprovedClient),
		pending:      make(map[string]*storage.PendingLogin),
	}

	// Load approved clients
	var approvedList storage.ApprovedClients
	if err := storage.LoadJSON(am.approvedPath, &approvedList); err == nil {
		for i := range approvedList.Clients {
			c := &approvedList.Clients[i]
			am.approved[c.Fingerprint] = c
		}
	}

	// Load pending logins
	var pendingList storage.PendingLogins
	if err := storage.LoadJSON(am.pendingPath, &pendingList); err == nil {
		for i := range pendingList.Logins {
			l := &pendingList.Logins[i]
			am.pending[l.Fingerprint] = l
		}
	}

	return am, nil
}

// RequestLogin handles a login request from a client.
func (am *AuthManager) RequestLogin(pubKeyPEM, fingerprint, signature string, timestamp int64) (*string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Check if already approved
	if client, ok := am.approved[fingerprint]; ok {
		// Client is approved, issue certificate
		pubKey, err := security.ParsePublicKeyPEM([]byte(pubKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}

		certPEM, err := am.ca.SignClientCert(pubKey, client.Name, 365*24*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("sign certificate: %w", err)
		}

		cert := string(certPEM)
		return &cert, nil
	}

	// Verify signature
	pubKey, err := security.ParsePublicKeyPEM([]byte(pubKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	// Verify the fingerprint matches the public key
	actualFingerprint := security.PublicKeyFingerprint(pubKey)
	if actualFingerprint != fingerprint {
		return nil, fmt.Errorf("fingerprint mismatch")
	}

	// Verify signature over timestamp
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))

	// ECDSA signature is r || s
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("invalid signature length")
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Add to pending
	am.pending[fingerprint] = &storage.PendingLogin{
		Fingerprint: fingerprint,
		PublicKey:   pubKeyPEM,
		RequestedAt: time.Now(),
	}

	if err := am.savePending(); err != nil {
		return nil, fmt.Errorf("save pending: %w", err)
	}

	return nil, nil
}

// Approve approves a pending login request.
func (am *AuthManager) Approve(fingerprint, name string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	pending, ok := am.pending[fingerprint]
	if !ok {
		return fmt.Errorf("no pending login for fingerprint: %s", fingerprint)
	}

	am.approved[fingerprint] = &storage.ApprovedClient{
		Fingerprint: fingerprint,
		Name:        name,
		ApprovedAt:  time.Now(),
	}

	delete(am.pending, fingerprint)

	if err := am.saveApproved(); err != nil {
		return fmt.Errorf("save approved: %w", err)
	}

	if err := am.savePending(); err != nil {
		return fmt.Errorf("save pending: %w", err)
	}

	// Store the public key for later certificate generation
	pubKeyPath := filepath.Join(am.configDir, "pending_keys", fingerprint+".pub")
	storage.SaveJSON(pubKeyPath, pending.PublicKey)

	return nil
}

// IsApproved checks if a fingerprint is approved.
func (am *AuthManager) IsApproved(fingerprint string) bool {
	am.mu.RLock()
	defer am.mu.RUnlock()
	_, ok := am.approved[fingerprint]
	return ok
}

// ListPending returns all pending login requests.
func (am *AuthManager) ListPending() []storage.PendingLogin {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make([]storage.PendingLogin, 0, len(am.pending))
	for _, p := range am.pending {
		result = append(result, *p)
	}
	return result
}

// ListApproved returns all approved clients.
func (am *AuthManager) ListApproved() []storage.ApprovedClient {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make([]storage.ApprovedClient, 0, len(am.approved))
	for _, c := range am.approved {
		result = append(result, *c)
	}
	return result
}

func (am *AuthManager) saveApproved() error {
	list := storage.ApprovedClients{
		Clients: make([]storage.ApprovedClient, 0, len(am.approved)),
	}
	for _, c := range am.approved {
		list.Clients = append(list.Clients, *c)
	}
	return storage.SaveJSON(am.approvedPath, &list)
}

func (am *AuthManager) savePending() error {
	list := storage.PendingLogins{
		Logins: make([]storage.PendingLogin, 0, len(am.pending)),
	}
	for _, l := range am.pending {
		list.Logins = append(list.Logins, *l)
	}
	return storage.SaveJSON(am.pendingPath, &list)
}

// SignAgentCSR signs a certificate signing request from an agent.
func (am *AuthManager) SignAgentCSR(csrPEM []byte, machineName string) ([]byte, error) {
	return am.ca.SignCSR(csrPEM, 365*24*time.Hour)
}

// GetCACert returns the CA certificate in PEM format.
func (am *AuthManager) GetCACert() []byte {
	return am.ca.CertPEM
}
