package signer

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var DEFAULT_SIGNER_TLS_CA_PATH = ""

func newSignerHTTPClient(timeoutValue, signerTLSCAPath string) (*http.Client, error) {
	return newSignerHTTPClientWithClientCert(timeoutValue, signerTLSCAPath, "", nil)
}

func newSignerHTTPClientWithClientCert(timeoutValue, signerTLSCAPath, clientCertPEM string, privateKey crypto.PrivateKey) (*http.Client, error) {
	timeout, _ := strconv.Atoi(strings.TrimSpace(timeoutValue))
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	var tlsConfig *tls.Config

	signerTLSCAPath = strings.TrimSpace(signerTLSCAPath)
	if signerTLSCAPath != "" {
		if strings.Contains(signerTLSCAPath, "://") {
			return nil, fmt.Errorf("signer TLS CA must be a local PEM file path: %s", signerTLSCAPath)
		}

		caPEM, err := os.ReadFile(signerTLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("Failed to read signer TLS CA certificate from %s: %w", signerTLSCAPath, err)
		}
		if len(strings.TrimSpace(string(caPEM))) != 0 {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("Failed to parse signer TLS CA certificate bundle")
			}

			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			}
		}
	}

	clientCertPEM = strings.TrimSpace(clientCertPEM)
	if clientCertPEM != "" || privateKey != nil {
		cert, err := newTLSClientCertificate(clientCertPEM, privateKey)
		if err != nil {
			return nil, err
		}
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if tlsConfig == nil {
		return client, nil
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("Failed to configure TLS transport: http.DefaultTransport is %T", http.DefaultTransport)
	}
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = tlsConfig
	client.Transport = transport
	return client, nil
}

func newTLSClientCertificate(clientCertPEM string, privateKey crypto.PrivateKey) (tls.Certificate, error) {
	if clientCertPEM == "" {
		return tls.Certificate{}, fmt.Errorf("ZTS client certificate PEM is required for mTLS")
	}
	if privateKey == nil {
		return tls.Certificate{}, fmt.Errorf("ZTS client certificate private key is required for mTLS")
	}

	certChain, leaf, err := parseClientCertificatePEM(clientCertPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	signerKey, ok := privateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("ZTS client certificate private key does not support signing")
	}
	if err := verifyClientCertificateKeyPair(leaf, signerKey); err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: certChain,
		PrivateKey:  signerKey,
		Leaf:        leaf,
	}, nil
}

func parseClientCertificatePEM(clientCertPEM string) ([][]byte, *x509.Certificate, error) {
	var certChain [][]byte
	rest := []byte(clientCertPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certChain = append(certChain, block.Bytes)
	}

	if len(certChain) == 0 {
		return nil, nil, fmt.Errorf("Failed to parse ZTS client certificate PEM")
	}

	leaf, err := x509.ParseCertificate(certChain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse ZTS client certificate: %w", err)
	}
	return certChain, leaf, nil
}

func verifyClientCertificateKeyPair(cert *x509.Certificate, privateKey crypto.Signer) error {
	certPublicKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("Failed to parse ZTS client certificate public key: %w", err)
	}
	privatePublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return fmt.Errorf("Failed to parse ZTS client certificate private key public key: %w", err)
	}
	if !bytes.Equal(certPublicKey, privatePublicKey) {
		return fmt.Errorf("ZTS client certificate does not match the private key")
	}
	return nil
}

func DefaultSignerTLSCAPath() string {
	defaultPath := strings.TrimSpace(DEFAULT_SIGNER_TLS_CA_PATH)
	if defaultPath == "" || strings.Contains(defaultPath, "://") || filepath.IsAbs(defaultPath) {
		return defaultPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultPath
	}
	return filepath.Join(home, defaultPath)
}
