package certstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)



// GeneratedStore is a certificate store that generates certificates on demand
type GeneratedStore struct {
	mu            sync.RWMutex
	cache         map[string]*tls.Certificate
	ca            *x509.Certificate
	caKey         *rsa.PrivateKey
	options      *StoreOptions
	cacheDuration time.Duration
}

// NewGeneratedStore creates a new store for auto-generated certificates
func NewGeneratedStore(options *StoreOptions) (*GeneratedStore, error) {
	if options == nil {
		return nil, fmt.Errorf("options is required")
	}

	s := &GeneratedStore{
		cache:         make(map[string]*tls.Certificate),
		options:       options,
		cacheDuration: options.CacheDuration,
	}

	// Generate or use provided CA
	if err := s.generateCA(); err != nil {
		return nil, fmt.Errorf("failed to generate CA: %v", err)
	}

	return s, nil
}

func (s *GeneratedStore) generateCA() error {
	var caKey *rsa.PrivateKey
	var caCert *x509.Certificate
	var err error

	// Use provided CA if available
	if s.options.CAKey != nil && s.options.CACert != nil {
		caKey = s.options.CAKey
		caCert = s.options.CACert
	} else {
		// Generate CA key
		caKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate CA private key: %v", err)
		}

		// Prepare CA certificate template
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return fmt.Errorf("failed to generate serial number: %v", err)
		}

		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: s.options.CommonName,
			},
			// Set validity period with small backdating for clock skew
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(s.options.DefaultTTL),
			// CA certs need KeyUsageCertSign to sign other certs
			// KeyUsageDigitalSignature for signing CRLs and OCSP responses
			// KeyUsageKeyEncipherment for encrypting private keys
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            1,
		}

		// Create CA certificate
		caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
		if err != nil {
			return fmt.Errorf("failed to create CA certificate: %v", err)
		}

		caCert, err = x509.ParseCertificate(caCertDER)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %v", err)
		}
	}

	s.caKey = caKey
	s.ca = caCert
	return nil
}

func (s *GeneratedStore) generateCertificate(serverName string, opts *CertificateOptions) (*tls.Certificate, error) {
	// Use default options if none provided
	if opts == nil {
		defaultOpts := NewCertificateOptions(serverName, s.options.DefaultTTL)
		opts = &defaultOpts
	}

	// Generate key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Prepare certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Get TTL from options or default
	ttl := opts.TTL
	if ttl == 0 {
		ttl = s.options.DefaultTTL
	}
	log.Printf("Initial TTL: %v", ttl)

	// Compute validity period with clock skew buffers
	notBefore, notAfter := ComputeValidityPeriod(ttl)
	log.Printf("Generating certificate for %s with TTL=%v: NotBefore=%v, NotAfter=%v", serverName, ttl, notBefore, notAfter)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              opts.KeyUsage,
		ExtKeyUsage:           opts.ExtKeyUsage,
		BasicConstraintsValid: true,
	}

	// Set IP addresses and DNS names from CertificateOptions
	template.IPAddresses = opts.IPAddresses
	template.DNSNames = opts.DNSNames

	// If no DNS names were provided, use the serverName as a fallback
	if len(template.DNSNames) == 0 {
		template.DNSNames = []string{serverName}
	}

	// For localhost/127.0.0.1, always add both
	if serverName == "localhost" || serverName == "127.0.0.1" || serverName == "::1" {
		// Add localhost to DNS names if not already present
		haveLocalhost := false
		for _, name := range template.DNSNames {
			if name == "localhost" {
				haveLocalhost = true
				break
			}
		}
		if !haveLocalhost {
			template.DNSNames = append(template.DNSNames, "localhost")
		}

		// Add localhost IPs if not already present
		haveIPv4 := false
		haveIPv6 := false
		for _, ip := range template.IPAddresses {
			if ip.Equal(net.ParseIP("127.0.0.1")) {
				haveIPv4 = true
			}
			if ip.Equal(net.ParseIP("::1")) {
				haveIPv6 = true
			}
		}
		if !haveIPv4 {
			template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
		}
		if !haveIPv6 {
			template.IPAddresses = append(template.IPAddresses, net.ParseIP("::1"))
		}
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, s.ca, &privKey.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes, s.ca.Raw},
		PrivateKey:  privKey,
		Leaf:        template,
	}

	return cert, nil
}

// GetCertificate gets or generates a certificate for the given server name
func (s *GeneratedStore) GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check cache first
	if cert, ok := s.cache[serverName]; ok {
		if time.Now().Before(cert.Leaf.NotAfter) {
			return cert, nil
		}
		delete(s.cache, serverName)
	}

	// Generate new certificate
	cert, err := s.generateCertificate(serverName, nil) // Use default options
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	s.cache[serverName] = cert
	return cert, nil
}

// mergeCertificateOptions merges store options with provided options, letting provided options take precedence
func (s *GeneratedStore) mergeCertificateOptions(serverName string, opts *CertificateOptions) *CertificateOptions {
	// Start with store defaults
	merged := &CertificateOptions{
		CommonName:    serverName,
		CacheDuration: s.cacheDuration,
		KeyUsage:      s.options.KeyUsage,
		ExtKeyUsage:   make([]x509.ExtKeyUsage, len(s.options.ExtKeyUsage)),
		IPAddresses:   []net.IP{},
		DNSNames:      []string{},
		TTL:           s.options.DefaultTTL,
	}

	// Copy ExtKeyUsage slice to avoid modifying store config
	copy(merged.ExtKeyUsage, s.options.ExtKeyUsage)
	// Note: IP addresses and DNS names are now only set via CertificateOptions

	// If no options provided, return store defaults
	if opts == nil {
		return merged
	}

	// Override with provided options
	if opts.CommonName != "" {
		merged.CommonName = opts.CommonName
	}
	if opts.TTL != 0 {
		merged.TTL = opts.TTL
	}
	if opts.CacheDuration != 0 {
		merged.CacheDuration = opts.CacheDuration
	}
	if opts.KeyUsage != 0 {
		merged.KeyUsage = opts.KeyUsage
	}
	// Always ensure both client and server auth are present
	if len(opts.ExtKeyUsage) > 0 {
		// Start with the required usages
		merged.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		// Add any additional usages that aren't already present
		for _, usage := range opts.ExtKeyUsage {
			if usage != x509.ExtKeyUsageClientAuth && usage != x509.ExtKeyUsageServerAuth {
				merged.ExtKeyUsage = append(merged.ExtKeyUsage, usage)
			}
		}
	}
	if len(opts.IPAddresses) > 0 {
		merged.IPAddresses = make([]net.IP, len(opts.IPAddresses))
		copy(merged.IPAddresses, opts.IPAddresses)
	}
	if len(opts.DNSNames) > 0 {
		merged.DNSNames = make([]string, len(opts.DNSNames))
		copy(merged.DNSNames, opts.DNSNames)
	}

	return merged
}

// getCachedCertificate returns a cached certificate if it exists and is still valid, otherwise returns nil
func (s *GeneratedStore) getCachedCertificate(serverName string) *tls.Certificate {
	// Check if certificate exists in cache
	cert, exists := s.cache[serverName]
	if !exists {
		return nil
	}

	// Parse the certificate if needed
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil
		}
		cert.Leaf = leaf
	}

	// Check if certificate has expired
	now := time.Now()
	if now.After(cert.Leaf.NotAfter) || now.Before(cert.Leaf.NotBefore) {
		// Remove expired certificate from cache
		delete(s.cache, serverName)
		return nil
	}

	return cert
}

// GetCertificateWithOptions gets or generates a certificate for the given server name with specific options
func (s *GeneratedStore) GetCertificateWithOptions(ctx context.Context, serverName string, opts *CertificateOptions) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Merge store options with provided options
	mergedOpts := s.mergeCertificateOptions(serverName, opts)

	// Check cache first
	if cert := s.getCachedCertificate(serverName); cert != nil {
		return cert, nil
	}

	// Generate new certificate
	cert, err := s.generateCertificate(serverName, mergedOpts)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	s.cache[serverName] = cert

	return cert, nil
}

// GetCertificateExpiry returns the expiry time of a certificate
func (s *GeneratedStore) GetCertificateExpiry(ctx context.Context, serverName string) (time.Time, error) {
	cert, err := s.GetCertificate(ctx, serverName)
	if err != nil {
		return time.Time{}, err
	}
	return cert.Leaf.NotAfter, nil
}

// GetCertPool returns a certificate pool containing the store's CA certificate
func (s *GeneratedStore) GetCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.ca)
	return pool
}

// GetCACertificate returns the CA certificate used by this store
func (s *GeneratedStore) GetCACertificate() *x509.Certificate {
	return s.ca
}

// GetCAPrivateKey returns the CA private key used by this store
func (s *GeneratedStore) GetCAPrivateKey() *rsa.PrivateKey {
	return s.caKey
}

// ClearCache clears the certificate cache and regenerates the CA certificate
func (s *GeneratedStore) ClearCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]*tls.Certificate)
	// Force regenerate CA
	s.options.CAKey = nil
	s.options.CACert = nil
	return s.generateCA()
}


