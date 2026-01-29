package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyPair holds a private key and optionally a certificate.
type KeyPair struct {
	PrivateKey  *ecdsa.PrivateKey
	Certificate *x509.Certificate
	KeyPEM      []byte
	CertPEM     []byte
}

// GenerateKeyPair creates a new ECDSA key pair.
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &KeyPair{
		PrivateKey: privateKey,
		KeyPEM:     keyPEM,
	}, nil
}

// LoadKeyPair loads a key pair from PEM-encoded key and certificate.
func LoadKeyPair(keyPEM, certPEM []byte) (*KeyPair, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	kp := &KeyPair{
		PrivateKey: privateKey,
		KeyPEM:     keyPEM,
	}

	if len(certPEM) > 0 {
		certBlock, _ := pem.Decode(certPEM)
		if certBlock == nil {
			return nil, errors.New("failed to decode certificate PEM")
		}

		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}

		kp.Certificate = cert
		kp.CertPEM = certPEM
	}

	return kp, nil
}

// LoadKeyPairFromFiles loads a key pair from files.
func LoadKeyPairFromFiles(keyPath, certPath string) (*KeyPair, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}

	var certPEM []byte
	if certPath != "" {
		certPEM, err = os.ReadFile(certPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
	}

	return LoadKeyPair(keyPEM, certPEM)
}

// SaveToFiles saves the key pair to files.
func (kp *KeyPair) SaveToFiles(keyPath, certPath string) error {
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	if err := os.WriteFile(keyPath, kp.KeyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	if certPath != "" && len(kp.CertPEM) > 0 {
		if err := os.WriteFile(certPath, kp.CertPEM, 0644); err != nil {
			return fmt.Errorf("write certificate: %w", err)
		}
	}

	return nil
}

// GenerateCSR creates a certificate signing request.
func (kp *KeyPair) GenerateCSR(commonName string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"ClusterSH"},
			CommonName:   commonName,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// SetCertificate sets the certificate for this key pair.
func (kp *KeyPair) SetCertificate(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	kp.Certificate = cert
	kp.CertPEM = certPEM
	return nil
}

// Fingerprint returns the SHA256 fingerprint of the public key.
func (kp *KeyPair) Fingerprint() string {
	return PublicKeyFingerprint(&kp.PrivateKey.PublicKey)
}

// PublicKeyPEM returns the public key in PEM format.
func (kp *KeyPair) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&kp.PrivateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicKeyPEM parses a PEM-encoded public key.
func ParsePublicKeyPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecdsaPub, nil
}
