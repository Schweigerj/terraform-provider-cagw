package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// TLSConfigInput controls how mutual TLS credentials are loaded.
type TLSConfigInput struct {
	PKCS12Path         string
	PKCS12Password     string
	CustomCABundlePath string
	InsecureSkipVerify bool
}

// NewTLSConfig loads the PKCS#12 bundle and constructs a tls.Config suitable for Entrust CA Gateway requests.
func NewTLSConfig(input TLSConfigInput) (*tls.Config, error) {
	if input.PKCS12Path == "" {
		return nil, fmt.Errorf("pkcs12 path is required")
	}

	content, err := os.ReadFile(input.PKCS12Path)
	if err != nil {
		return nil, fmt.Errorf("reading pkcs12 file: %w", err)
	}

	privateKey, certificate, chain, err := pkcs12.DecodeChain(content, input.PKCS12Password)
	if err != nil {
		return nil, fmt.Errorf("decoding pkcs12 file: %w", err)
	}

	tlsCert := tls.Certificate{
		PrivateKey:  privateKey,
		Certificate: append([][]byte{certificate.Raw}, encodeChain(chain)...),
		Leaf:        certificate,
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: input.InsecureSkipVerify, //nolint:gosec // optionally set for development.
	}

	if input.CustomCABundlePath != "" {
		rootCAs, err := loadCustomCABundle(input.CustomCABundlePath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = rootCAs
	}

	return tlsConfig, nil
}

func loadCustomCABundle(path string) (*x509.CertPool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle %q: %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(content) {
		return nil, fmt.Errorf("failed to parse custom CA bundle: %s", path)
	}

	return pool, nil
}

func encodeChain(chain []*x509.Certificate) [][]byte {
	if len(chain) == 0 {
		return nil
	}

	result := make([][]byte, len(chain))
	for i, cert := range chain {
		result[i] = cert.Raw
	}

	return result
}
