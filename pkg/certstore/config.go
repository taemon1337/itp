package certstore

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"time"
	"log"
)

// Config holds all configuration for certificate store
type Config struct {
	// CA Certificate options
	CommonName    string
	KeyUsage      x509.KeyUsage
	ExtKeyUsage   []x509.ExtKeyUsage
	CAKey         *rsa.PrivateKey   // Optional: existing CA private key
	CACert        *x509.Certificate // Optional: existing CA certificate

	// Generated Certificate options
	TTL time.Duration // Duration for generated certificates
	KeyUsageForCerts      x509.KeyUsage
	ExtKeyUsageForCerts   []x509.ExtKeyUsage
	IPAddresses   []net.IP  // Optional: IP addresses to include as SANs
	DNSNames      []string  // Optional: DNS names to include as SANs

	// Cache options
	CacheDuration time.Duration // Duration to cache certificates in memory


}

// ComputeValidityPeriod computes NotBefore and NotAfter times for a certificate given a TTL.
// NotBefore is set to 1 hour before current time to handle clock skew.
// TTL is extended by 2 hours (1 hour on each side) to handle clock skew.
func ComputeValidityPeriod(ttl time.Duration) (notBefore, notAfter time.Time) {
	now := time.Now()
	notBefore = now.Add(-1 * time.Hour) // Backdate by 1 hour for clock skew
	notAfter = now.Add(ttl + 2 * time.Hour) // Add 2 hours to TTL for clock skew (1 hour each side)
	log.Printf("NotBefore: %v, NotAfter: %v", notBefore, notAfter)
	return
}

// NewCertStoreConfig returns a new Config with default values
// commonName is required, validityPeriod is optional (defaults to 1 year if not specified)
func NewCertStoreConfig(commonName string, validityPeriod ...time.Duration) *Config {
	
	// Set default validity period to 1 year if not specified
	validity := 365 * 24 * time.Hour
	if len(validityPeriod) > 0 && validityPeriod[0] > 0 {
		validity = validityPeriod[0]
	}

	return &Config{
		// Store defaults
		CommonName:     commonName,
		TTL:           validity,
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CacheDuration:  time.Hour,

		// Generated Certificate defaults
		KeyUsageForCerts:      x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsageForCerts:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},


	}
}

