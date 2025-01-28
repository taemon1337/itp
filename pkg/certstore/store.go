package certstore

import (
	"context"
	"crypto/tls"
	"time"
)

// Store is the interface for certificate stores
type Store interface {
	GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error)
	PutCertificate(ctx context.Context, serverName string, cert *tls.Certificate) error
	RemoveCertificate(ctx context.Context, serverName string) error
	GetCertificateExpiry(ctx context.Context, serverName string) (time.Time, error)
}

// Options contains common configuration for certificate stores
type Options struct {
	// CacheDuration specifies how long to cache certificates in memory
	CacheDuration time.Duration

	// DefaultTTL specifies the TTL for newly generated certificates
	DefaultTTL time.Duration
}

// cachedCert represents a cached certificate with its expiry time
type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}
