package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/rsa"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/itp/pkg/certstore"
	"github.com/stretchr/testify/assert"
)

func TestNewTLSConfig(t *testing.T) {
	// Create a GeneratedStore for test certificates
	store, err := certstore.NewGeneratedStore(certstore.StoreOptions{
		CommonName:    "Test CA",
		TTL:          24 * time.Hour,
		CacheDuration: 5 * time.Minute,
	})
	assert.NoError(t, err)

	// Get a test certificate
	cert, err := store.GetCertificate(context.Background(), "test.example.com")
	assert.NoError(t, err)

	// Get CA certificate
	caCert := store.GetCACertificate()
	assert.NotNil(t, caCert)

	// Encode certificates and key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey)),
	})

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	// Create temporary test files
	certFile, err := ioutil.TempFile("", "cert")
	assert.NoError(t, err)
	defer os.Remove(certFile.Name())
	_, err = certFile.Write(certPEM)
	assert.NoError(t, err)
	certFile.Close()

	keyFile, err := ioutil.TempFile("", "key")
	assert.NoError(t, err)
	defer os.Remove(keyFile.Name())
	_, err = keyFile.Write(keyPEM)
	assert.NoError(t, err)
	keyFile.Close()

	caFile, err := ioutil.TempFile("", "ca")
	assert.NoError(t, err)
	defer os.Remove(caFile.Name())
	_, err = caFile.Write(caPEM)
	assert.NoError(t, err)
	caFile.Close()

	tests := []struct {
		name        string
		config      Config
		expectError bool
	}{
		{
			name: "Valid Config",
			config: Config{
				CertFile: certFile.Name(),
				KeyFile:  keyFile.Name(),
				CAFile:   caFile.Name(),
			},
			expectError: false,
		},
		{
			name: "Invalid Cert File",
			config: Config{
				CertFile: "nonexistent.crt",
				KeyFile:  keyFile.Name(),
				CAFile:   caFile.Name(),
			},
			expectError: true,
		},
		{
			name: "Invalid Key File",
			config: Config{
				CertFile: certFile.Name(),
				KeyFile:  "nonexistent.key",
				CAFile:   caFile.Name(),
			},
			expectError: true,
		},
		{
			name: "Invalid CA File",
			config: Config{
				CertFile: certFile.Name(),
				KeyFile:  keyFile.Name(),
				CAFile:   "nonexistent.ca",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig, err := NewTLSConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, tlsConfig)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig)
				assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
				assert.Len(t, tlsConfig.Certificates, 1)
				assert.NotNil(t, tlsConfig.ClientCAs)
			}
		})
	}
}
