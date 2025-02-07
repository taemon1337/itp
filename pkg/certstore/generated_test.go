package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestGeneratedStore(t *testing.T) {
	// Test cases for certificate generation
	tests := []struct {
		name       string
		serverName string
		opts       *CertificateOptions
		wantErr    bool
	}{
		{
			name:       "Basic certificate",
			serverName: "example.com",
			opts:       nil, // Use default options
			wantErr:    false,
		},
		{
			name:       "Custom duration certificate",
			serverName: "custom.example.com",
			opts: &CertificateOptions{
				CommonName:    "custom.example.com",
				TTL:           24 * time.Hour, // Using TTL here as it's a per-cert override
				KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
				DNSNames:    []string{"custom.example.com", "www.custom.example.com"},
			},
			wantErr: false,
		},
	}

	// Create a store with default options
	storeOpts := NewStoreOptions("Test CA")
	store, err := NewGeneratedStore(&storeOpts)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get certificate with options
			cert, err := store.GetCertificateWithOptions(ctx, tt.serverName, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Verify certificate
			if cert == nil {
				t.Error("GetCertificate() returned nil certificate")
				return
			}

			// Parse the certificate
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Errorf("Failed to parse certificate: %v", err)
				return
			}

			// Basic certificate checks
			if x509Cert.Subject.CommonName != tt.serverName {
				t.Errorf("Certificate CommonName = %v, want %v", x509Cert.Subject.CommonName, tt.serverName)
			}

			// Check certificate validity period
			now := time.Now()
			if now.Before(x509Cert.NotBefore) {
				t.Error("Certificate is not yet valid")
			}
			if now.After(x509Cert.NotAfter) {
				t.Error("Certificate has expired")
			}

			// Check custom options if provided
			if tt.opts != nil {
				// Check SANs if specified
				if len(tt.opts.IPAddresses) > 0 {
					if len(x509Cert.IPAddresses) != len(tt.opts.IPAddresses) {
						t.Errorf("Certificate has %d IP addresses, want %d", len(x509Cert.IPAddresses), len(tt.opts.IPAddresses))
					}
				}
				if len(tt.opts.DNSNames) > 0 {
					if len(x509Cert.DNSNames) != len(tt.opts.DNSNames) {
						t.Errorf("Certificate has %d DNS names, want %d", len(x509Cert.DNSNames), len(tt.opts.DNSNames))
					}
				}
			}

			// Test certificate chain
			if len(cert.Certificate) != 2 {
				t.Error("Certificate chain should contain exactly 2 certificates (leaf + CA)")
			}

			// Verify the certificate can be used in a TLS config
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}
			if tlsConfig == nil {
				t.Error("Failed to create TLS config with certificate")
			}
		})
	}
}

func TestGeneratedStoreExpiry(t *testing.T) {
	// Create a store with default options
	storeOpts := NewStoreOptions("Test CA")
	store, err := NewGeneratedStore(&storeOpts)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	ctx := context.Background()
	serverName := "expiry.example.com"

	// Get initial certificate
	_, err = store.GetCertificate(ctx, serverName)
	if err != nil {
		t.Fatalf("Failed to get initial certificate: %v", err)
	}

	// Check expiry
	expiry, err := store.GetCertificateExpiry(ctx, serverName)
	if err != nil {
		t.Fatalf("Failed to get certificate expiry: %v", err)
	}

	// Verify expiry is in the future
	if !expiry.After(time.Now()) {
		t.Error("Certificate expiry should be in the future")
	}

	// Verify expiry matches default duration
	expectedExpiry := time.Now().Add(storeOpts.DefaultTTL)
	if diff := expectedExpiry.Sub(expiry); diff > time.Hour || diff < -time.Hour {
		t.Errorf("Certificate expiry differs from expected by %v", diff)
	}
}
