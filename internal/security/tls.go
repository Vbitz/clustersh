package security

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// NewServerTLSConfig creates a TLS config for the coordinator server.
func NewServerTLSConfig(ca *CA, serverKeyPair *KeyPair) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverKeyPair.CertPEM, serverKeyPair.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Certificate)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// NewClientTLSConfig creates a TLS config for clients connecting to the coordinator.
func NewClientTLSConfig(caCertPEM []byte, clientKeyPair *KeyPair) (*tls.Config, error) {
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	cert, err := tls.X509KeyPair(clientKeyPair.CertPEM, clientKeyPair.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// NewAgentTLSConfig creates a TLS config for agents connecting to the coordinator.
func NewAgentTLSConfig(caCertPEM []byte, agentKeyPair *KeyPair) (*tls.Config, error) {
	return NewClientTLSConfig(caCertPEM, agentKeyPair)
}
