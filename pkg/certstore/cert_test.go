package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"fmt"
	"testing"
	"strings"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCertificateWithOptions(t *testing.T) {
	// Create a store with default options
	storeOpts := NewStoreOptions("Test CA")
	storeOpts.DefaultTTL = 365 * 24 * time.Hour
	store, err := NewGeneratedStore(&storeOpts)
	require.NoError(t, err)

	// Test cases for certificate generation with options
	tests := []struct {
		name       string
		serverName string
		opts       *CertificateOptions
		wantErr    bool
	}{
		{
			name:       "Basic certificate with default options",
			serverName: "example.com",
			opts:       nil, // Use store defaults
			wantErr:    false,
		},
		{
			name:       "Certificate with custom TTL",
			serverName: "custom.example.com",
			opts: &CertificateOptions{
				CommonName:  "custom.example.com",
				IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
				DNSNames:    []string{"custom.example.com", "www.custom.example.com"},
			},
			wantErr: false,
		},
		{
			name:       "Certificate with immediate validity",
			serverName: "immediate.example.com",
			opts: &CertificateOptions{
				CommonName: "immediate.example.com",
				TTL:        0, // Immediate validity
			},
			wantErr: false,
		},
		{
			name:       "Certificate with custom key usage",
			serverName: "keyusage.example.com",
			opts: &CertificateOptions{
				CommonName:  "keyusage.example.com",
				KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			},
			wantErr: false,
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get certificate with options
			cert, err := store.GetCertificateWithOptions(ctx, tt.serverName, tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertificateWithOptions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Basic certificate validation
			require.NotNil(t, cert)
			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			require.NoError(t, err)

			// Verify certificate fields
			assert.Equal(t, tt.serverName, x509Cert.Subject.CommonName)
			
			// Verify time validity
			now := time.Now()
			assert.True(t, now.After(x509Cert.NotBefore) || now.Equal(x509Cert.NotBefore), 
				"Certificate NotBefore (%v) should be before or equal to now (%v)", x509Cert.NotBefore, now)
			assert.True(t, now.Before(x509Cert.NotAfter), 
				"Certificate NotAfter (%v) should be after now (%v)", x509Cert.NotAfter, now)

			// Verify certificate chain
			assert.Equal(t, 2, len(cert.Certificate), 
				"Certificate chain should contain exactly 2 certificates (leaf + CA)")

			// Verify certificate properties
			t.Run("Certificate Properties", func(t *testing.T) {
				// Parse certificates
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				require.NoError(t, err)
				ca, err := x509.ParseCertificate(cert.Certificate[1])
				require.NoError(t, err)

				// Verify server name
				assert.Equal(t, tt.serverName, leaf.Subject.CommonName)

				// Verify key usage
				expectedUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
				assert.ElementsMatch(t, expectedUsages, leaf.ExtKeyUsage)

				// Verify CA certificate
				assert.True(t, ca.IsCA)
				assert.Equal(t, ca.Subject.CommonName, leaf.Issuer.CommonName)

				// Verify certificate can be validated
				roots := x509.NewCertPool()
				roots.AddCert(ca)
				opts := x509.VerifyOptions{
					DNSName: tt.serverName,
					Roots:   roots,
				}
				_, err = leaf.Verify(opts)
				assert.NoError(t, err)
			})

			// Verify SANs if specified
			if tt.opts != nil && tt.opts.IPAddresses != nil {
				assert.Equal(t, len(tt.opts.IPAddresses), len(x509Cert.IPAddresses))
				if len(tt.opts.IPAddresses) == len(x509Cert.IPAddresses) {
					for i, ip := range tt.opts.IPAddresses {
						assert.Equal(t, ip.String(), x509Cert.IPAddresses[i].String())
					}
				}
			}
			if tt.opts != nil && tt.opts.DNSNames != nil {
				// Convert slices to maps for set comparison
				expectedDNS := make(map[string]bool)
				actualDNS := make(map[string]bool)
				for _, dns := range tt.opts.DNSNames {
					expectedDNS[dns] = true
				}
				for _, dns := range x509Cert.DNSNames {
					actualDNS[dns] = true
				}
				assert.Equal(t, expectedDNS, actualDNS, "DNS names should match regardless of order")
			}
		})
	}
}

func TestCertificateTTL(t *testing.T) {
	// Create store with default config
	storeOpts := NewStoreOptions("test.example.com")
	storeOpts.DefaultTTL = 365 * 24 * time.Hour
	store, err := NewGeneratedStore(&storeOpts)
	require.NoError(t, err)

	ctx := context.Background()
	serverName := "test.example.com"

	// Create certificate options with 1 day validity
	opts := &CertificateOptions{
		CommonName: serverName,
		TTL:        24 * time.Hour,	
	}

	// Get certificate with custom TTL
	cert, err := store.GetCertificateWithOptions(ctx, serverName, opts)
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	// Verify TTL
	expectedValidity := 24 * time.Hour
	actualValidity := x509Cert.NotAfter.Sub(x509Cert.NotBefore)
	assert.True(t, actualValidity >= expectedValidity-time.Hour && 
		actualValidity <= expectedValidity+time.Hour,
		"Certificate TTL should be approximately %v, got %v", 
		expectedValidity, actualValidity)
}

// certPoolContains checks if a certificate pool contains a specific certificate
// keyUsageToString converts x509.KeyUsage to a human-readable string
func keyUsageToString(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	if len(usages) == 0 {
		return fmt.Sprintf("Unknown(%d)", usage)
	}
	return strings.Join(usages, ", ")
}

// clientAuthToString converts tls.ClientAuthType to a human-readable string
func clientAuthToString(authType tls.ClientAuthType) string {
	switch authType {
	case tls.NoClientCert:
		return "NoClientCert"
	case tls.RequestClientCert:
		return "RequestClientCert"
	case tls.RequireAnyClientCert:
		return "RequireAnyClientCert"
	case tls.VerifyClientCertIfGiven:
		return "VerifyClientCertIfGiven"
	case tls.RequireAndVerifyClientCert:
		return "RequireAndVerifyClientCert"
	default:
		return fmt.Sprintf("Unknown(%d)", authType)
	}
}

// certPoolContains checks if a certificate pool contains a specific certificate
func certPoolContains(pool *x509.CertPool, cert *x509.Certificate) bool {
	if pool == nil || cert == nil {
		return false
	}

	// Get the raw subject bytes from the test certificate
	testSubject := cert.RawSubject

	// Get all subjects from the pool
	subjects := pool.Subjects()

	// Look for a matching subject
	for _, subject := range subjects {
		if string(subject) == string(testSubject) {
			return true
		}
	}
	return false
}

// TestCertificateChainAndCA verifies that certificates are properly chained
// and that the CA certificate is properly configured
func TestCertificateChainAndCA(t *testing.T) {
	// Create store with default config
	storeOpts := NewStoreOptions("ca.example.com")
	storeOpts.DefaultTTL = 365 * 24 * time.Hour
	store, err := NewGeneratedStore(&storeOpts)
	require.NoError(t, err)

	ctx := context.Background()
	serverName := "server.example.com"

	// Get certificate with default options
	cert, err := store.GetCertificateWithOptions(ctx, serverName, nil)
	require.NoError(t, err)

	// Test validity period
	t.Run("TTL", func(t *testing.T) {
		// Parse both certificates
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		ca, err := x509.ParseCertificate(cert.Certificate[1])
		require.NoError(t, err)

		// Verify leaf certificate validity
		expectedNotBefore := time.Now().Add(-1 * time.Hour) // Default from NewCertStoreConfig
		expectedNotAfter := expectedNotBefore.Add(365 * 24 * time.Hour) // Default from NewCertStoreConfig

		assert.True(t, leaf.NotBefore.Sub(expectedNotBefore) > -2*time.Hour && 
			leaf.NotBefore.Sub(expectedNotBefore) < 2*time.Hour,
			"Leaf certificate NotBefore should be within 2 hours of expected time")

		assert.True(t, leaf.NotAfter.Sub(expectedNotAfter) > -2*time.Hour && 
			leaf.NotAfter.Sub(expectedNotAfter) < 2*time.Hour,
			"Leaf certificate NotAfter should be within 2 hours of expected time")

		// Verify CA certificate validity
		assert.True(t, ca.NotBefore.Sub(expectedNotBefore) > -2*time.Hour && 
			ca.NotBefore.Sub(expectedNotBefore) < 2*time.Hour,
			"CA certificate NotBefore should be within 2 hours of expected time")

		assert.True(t, ca.NotAfter.Sub(expectedNotAfter) > -2*time.Hour && 
			ca.NotAfter.Sub(expectedNotAfter) < 2*time.Hour,
			"CA certificate NotAfter should be within 2 hours of expected time")
	})

	// Test client authentication requirements
	t.Run("Client Authentication", func(t *testing.T) {
		// Parse both certificates
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		ca, err := x509.ParseCertificate(cert.Certificate[1])
		require.NoError(t, err)

		// Verify that ExtKeyUsage includes client and server auth
		expectedUsages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		assert.ElementsMatch(t, expectedUsages, leaf.ExtKeyUsage,
			"Leaf certificate should have both client and server auth key usage")

		// Verify key usage flags
		expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		assert.Equal(t, expectedKeyUsage, leaf.KeyUsage,
			"Leaf certificate should have key usage flags %s, got %s",
			keyUsageToString(expectedKeyUsage),
			keyUsageToString(leaf.KeyUsage))

		// Verify CA key usage flags
		expectedCAKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		assert.Equal(t, expectedCAKeyUsage, ca.KeyUsage,
			"CA certificate should have key usage flags %s, got %s",
			keyUsageToString(expectedCAKeyUsage),
			keyUsageToString(ca.KeyUsage))
	})

	// Test certificate chain
	t.Run("Certificate Chain", func(t *testing.T) {
		// Verify we have a certificate chain (leaf + CA)
		assert.Equal(t, 2, len(cert.Certificate), "Certificate should have a chain of 2 certificates (leaf + CA)")

		// Parse both certificates
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		ca, err := x509.ParseCertificate(cert.Certificate[1])
		require.NoError(t, err)

		// Verify leaf certificate
		assert.Equal(t, serverName, leaf.Subject.CommonName)
		assert.Equal(t, ca.Subject.CommonName, leaf.Issuer.CommonName, "Leaf certificate should be issued by our CA")

		// Verify CA certificate
		assert.Equal(t, ca.Subject.CommonName, ca.Issuer.CommonName, "CA should be self-signed")
		assert.True(t, ca.IsCA, "CA certificate should have CA flag set")
	})

	// Test CA pool
	t.Run("CA Pool", func(t *testing.T) {
		// Get the CA pool
		pool := store.GetCertPool()
		require.NotNil(t, pool)

		// Verify our CA is in the pool
		ca := store.GetCACertificate()
		require.NotNil(t, ca)
		assert.True(t, certPoolContains(pool, ca))

		// Verify we can validate the leaf certificate using the CA pool
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)
		
		roots := x509.NewCertPool()
		roots.AddCert(ca)

		opts := x509.VerifyOptions{
			DNSName: serverName,
			Roots:   roots,
		}

		_, err = leaf.Verify(opts)
		assert.NoError(t, err, "Leaf certificate should verify against our CA")
	})
}

