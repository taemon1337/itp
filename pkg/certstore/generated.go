package certstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// GeneratedStore is a certificate store that generates certificates on demand
type GeneratedStore struct {
	mu          sync.RWMutex
	certs       map[string]*tls.Certificate
	ca          *x509.Certificate
	caKey       *rsa.PrivateKey
	expiry      time.Duration
	commonName  string
	defaultTTL  time.Duration
	cache       map[string]*tls.Certificate
	cacheMu     sync.RWMutex
	cacheDuration time.Duration
}

// GeneratedOptions contains options for the generated certificate store
type GeneratedOptions struct {
	CommonName string
	Expiry     time.Duration
	DefaultTTL time.Duration
	CacheDuration time.Duration
	CAKey      *rsa.PrivateKey  // Optional: existing CA private key
	CACert     *x509.Certificate // Optional: existing CA certificate
}

// NewGeneratedStore creates a new store for auto-generated certificates
func NewGeneratedStore(opts GeneratedOptions) (*GeneratedStore, error) {
	var caKey *rsa.PrivateKey
	var caCert *x509.Certificate
	var err error

	if opts.CAKey != nil && opts.CACert != nil {
		caKey = opts.CAKey
		caCert = opts.CACert
	} else {
		// Generate CA key
		caKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA key: %v", err)
		}

		// Generate CA cert
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: opts.CommonName + "-ca",
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(opts.Expiry),
			IsCA:                  true,
			KeyUsage:             x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		}

		caCertBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA certificate: %v", err)
		}

		caCert, err = x509.ParseCertificate(caCertBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
		}
	}

	return &GeneratedStore{
		certs:       make(map[string]*tls.Certificate),
		ca:          caCert,
		caKey:       caKey,
		expiry:      opts.Expiry,
		commonName:  opts.CommonName,
		defaultTTL:  opts.DefaultTTL,
		cache:       make(map[string]*tls.Certificate),
		cacheDuration: opts.CacheDuration,
	}, nil
}

// GetCACertificate returns the CA certificate used by this store
func (s *GeneratedStore) GetCACertificate() *x509.Certificate {
	return s.ca
}

// GetCAPrivateKey returns the CA private key used by this store
func (s *GeneratedStore) GetCAPrivateKey() *rsa.PrivateKey {
	return s.caKey
}

func (s *GeneratedStore) generateCertificate(serverName string) (*tls.Certificate, error) {
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

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(s.defaultTTL),
		KeyUsage:             x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add appropriate SANs
	host := serverName
	if strings.Contains(serverName, ":") {
		var err error
		host, _, err = net.SplitHostPort(serverName)
		if err != nil {
			// If SplitHostPort fails, use the full serverName
			host = serverName
		}
	}

	// Add SANs based on the host (without port)
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
		// Also add the original serverName (with port) as DNS name for maximum compatibility
		template.DNSNames = []string{serverName}
	} else {
		template.DNSNames = []string{host, serverName}
	}

	// For localhost/127.0.0.1, add both
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		template.DNSNames = append(template.DNSNames, "localhost")
		template.IPAddresses = append(template.IPAddresses,
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		)
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

func (s *GeneratedStore) GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	s.cacheMu.RLock()
	if cached, ok := s.cache[serverName]; ok {
		if time.Now().Before(cached.Leaf.NotAfter) {
			s.cacheMu.RUnlock()
			return cached, nil
		}
	}
	s.cacheMu.RUnlock()

	s.mu.RLock()
	cert, ok := s.certs[serverName]
	s.mu.RUnlock()

	if ok && time.Now().Before(cert.Leaf.NotAfter) {
		return cert, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check again in case another goroutine generated it
	cert, ok = s.certs[serverName]
	if ok && time.Now().Before(cert.Leaf.NotAfter) {
		return cert, nil
	}

	// Generate new certificate
	cert, err := s.generateCertificate(serverName)
	if err != nil {
		return nil, err
	}

	s.certs[serverName] = cert
	s.cacheMu.Lock()
	s.cache[serverName] = cert
	s.cacheMu.Unlock()
	return cert, nil
}

func (s *GeneratedStore) PutCertificate(ctx context.Context, serverName string, cert *tls.Certificate) error {
	s.mu.Lock()
	s.certs[serverName] = cert
	s.mu.Unlock()
	s.cacheMu.Lock()
	s.cache[serverName] = cert
	s.cacheMu.Unlock()
	return nil
}

func (s *GeneratedStore) RemoveCertificate(ctx context.Context, serverName string) error {
	s.mu.Lock()
	delete(s.certs, serverName)
	s.mu.Unlock()
	s.cacheMu.Lock()
	delete(s.cache, serverName)
	s.cacheMu.Unlock()
	return nil
}

func (s *GeneratedStore) GetCertificateExpiry(ctx context.Context, serverName string) (time.Time, error) {
	cert, err := s.GetCertificate(ctx, serverName)
	if err != nil {
		return time.Time{}, err
	}
	return cert.Leaf.NotAfter, nil
}
