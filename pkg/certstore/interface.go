package certstore

import (
	"context"
	"crypto/tls"
	"time"
)

// Store defines the interface for certificate management
type Store interface {
	// GetCertificate returns a TLS certificate for the given server name
	// It may fetch from cache or generate/fetch a new one if needed
	GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error)

	// PutCertificate stores a certificate in the store
	PutCertificate(ctx context.Context, serverName string, cert *tls.Certificate) error

	// RemoveCertificate removes a certificate from the store
	RemoveCertificate(ctx context.Context, serverName string) error

	// GetCertificateExpiry returns the expiration time of a certificate
	GetCertificateExpiry(ctx context.Context, serverName string) (time.Time, error)
}

// Options contains common configuration for certificate stores
type Options struct {
	// CacheDuration specifies how long to cache certificates in memory
	CacheDuration time.Duration

	// DefaultTTL specifies the TTL for newly generated certificates
	DefaultTTL time.Duration
}
