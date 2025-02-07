package certstore

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

// CertificateOptions contains options for creating a certificate
type CertificateOptions struct {
	CommonName    string
	CacheDuration time.Duration
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage
	IPAddresses   []net.IP // Optional: IP addresses to include as SANs
	DNSNames      []string // Optional: DNS names to include as SANs
	TTL           time.Duration // Optional: override store's default TTL
}

// NewCertificateOptions creates certificate options with sensible defaults
func NewCertificateOptions(commonName string, duration time.Duration) CertificateOptions {
	return CertificateOptions{
		CommonName:    commonName,
		CacheDuration: time.Hour,
		KeyUsage:      x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		TTL:           duration,
	}
}

// StoreOptions contains options for creating a new certificate store
type StoreOptions struct {
	CommonName    string
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage
	CAKey         *rsa.PrivateKey   // Optional: existing CA private key
	CACert        *x509.Certificate // Optional: existing CA certificate
	CacheDuration time.Duration
	DefaultTTL    time.Duration // Default duration for generated certificates
}

// NewStoreOptions creates store options with sensible defaults
func NewStoreOptions(commonName string) StoreOptions {
	return StoreOptions{
		CommonName:    commonName,
		KeyUsage:      x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CacheDuration: time.Hour,
		DefaultTTL:    30 * 24 * time.Hour, // 30 days for generated certs
	}
}

// Store defines the interface for certificate stores
type Store interface {
	// GetCertificate gets or generates a certificate for the given server name
	GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error)

	// GetCertificateWithOptions gets or generates a certificate with specific options
	GetCertificateWithOptions(ctx context.Context, serverName string, config *CertificateOptions) (*tls.Certificate, error)

	// GetCertificateExpiry returns the expiry time of a certificate
	GetCertificateExpiry(ctx context.Context, serverName string) (time.Time, error)

	// GetCertPool returns a certificate pool containing the store's CA certificate
	GetCertPool() *x509.CertPool

	// GetCACertificate returns the CA certificate used by this store
	GetCACertificate() *x509.Certificate

	// GetCAPrivateKey returns the CA private key used by this store
	GetCAPrivateKey() *rsa.PrivateKey


}

// cachedCert represents a cached certificate with its expiry time
type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}
