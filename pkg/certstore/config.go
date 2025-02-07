package certstore

import (
	"crypto/rsa"
	"crypto/x509"
	"net"
	"time"
)

// Config holds all configuration for certificate store
type Config struct {
	// CA Certificate options
	CommonName    string
	NotBefore     time.Time
	NotAfter      time.Time
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

// NewCertStoreConfig returns a new Config with default values
// commonName is required, validityPeriod is optional (defaults to 1 year if not specified)
func NewCertStoreConfig(commonName string, validityPeriod ...time.Duration) *Config {
	now := time.Now()
	
	// Set default validity period to 1 year if not specified
	validity := 365 * 24 * time.Hour
	if len(validityPeriod) > 0 && validityPeriod[0] > 0 {
		validity = validityPeriod[0]
	}

	return &Config{
		// Store defaults
		CommonName:     commonName,
		NotBefore:      now.Add(-1 * time.Hour), // Small backdating for clock skew
		NotAfter:       now.Add(validity),
		KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CacheDuration:  time.Hour,

		// Generated Certificate defaults
		KeyUsageForCerts:      x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsageForCerts:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},


	}
}

