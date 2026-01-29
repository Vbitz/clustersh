package security

import (
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	if ca.Certificate == nil {
		t.Error("CA certificate is nil")
	}
	if ca.PrivateKey == nil {
		t.Error("CA private key is nil")
	}
	if len(ca.CertPEM) == 0 {
		t.Error("CA cert PEM is empty")
	}
	if len(ca.KeyPEM) == 0 {
		t.Error("CA key PEM is empty")
	}

	// Verify it's a CA certificate
	if !ca.Certificate.IsCA {
		t.Error("Certificate is not marked as CA")
	}
}

func TestCALoadAndSave(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	// Test LoadCA
	ca2, err := LoadCA(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatalf("LoadCA() error = %v", err)
	}

	if ca2.Certificate.SerialNumber.Cmp(ca.Certificate.SerialNumber) != 0 {
		t.Error("Loaded certificate has different serial number")
	}
}

func TestSignCSR(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	// Generate a keypair and CSR
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	csrPEM, err := kp.GenerateCSR("test-client")
	if err != nil {
		t.Fatalf("GenerateCSR() error = %v", err)
	}

	// Sign the CSR
	certPEM, err := ca.SignCSR(csrPEM, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR() error = %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("Signed certificate is empty")
	}

	// Verify the certificate can be set on the keypair
	if err := kp.SetCertificate(certPEM); err != nil {
		t.Fatalf("SetCertificate() error = %v", err)
	}

	if kp.Certificate == nil {
		t.Error("Certificate not set on keypair")
	}

	if kp.Certificate.Subject.CommonName != "test-client" {
		t.Errorf("Certificate CN = %s, want test-client", kp.Certificate.Subject.CommonName)
	}
}

func TestSignClientCert(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	certPEM, err := ca.SignClientCert(&kp.PrivateKey.PublicKey, "test-user", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignClientCert() error = %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("Signed certificate is empty")
	}

	if err := kp.SetCertificate(certPEM); err != nil {
		t.Fatalf("SetCertificate() error = %v", err)
	}

	if kp.Certificate.Subject.CommonName != "test-user" {
		t.Errorf("Certificate CN = %s, want test-user", kp.Certificate.Subject.CommonName)
	}
}

func TestFingerprint(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA() error = %v", err)
	}

	fp, err := Fingerprint(ca.CertPEM)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}

	if len(fp) != 64 { // SHA256 hex = 64 chars
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Same cert should have same fingerprint
	fp2, _ := Fingerprint(ca.CertPEM)
	if fp != fp2 {
		t.Error("Same certificate has different fingerprints")
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	fp := PublicKeyFingerprint(&kp.PrivateKey.PublicKey)
	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64", len(fp))
	}

	// Same key should have same fingerprint
	fp2 := kp.Fingerprint()
	if fp != fp2 {
		t.Error("Same key has different fingerprints")
	}
}
