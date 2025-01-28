package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// GeneratedStore implements Store interface using auto-generated certificates
type GeneratedStore struct {
	cache         map[string]*cachedCert
	cacheMu       sync.RWMutex
	cacheDuration time.Duration
	defaultTTL    time.Duration
	caKey         *ecdsa.PrivateKey
	caCert        *x509.Certificate
}

// GeneratedOptions contains options for the generated certificate store
type GeneratedOptions struct {
	Options
	CAKey         *ecdsa.PrivateKey  // Optional: existing CA private key
	CACertificate *x509.Certificate  // Optional: existing CA certificate
}

// GetCACertificate returns the CA certificate used by this store
func (s *GeneratedStore) GetCACertificate() *x509.Certificate {
	return s.caCert
}

// GetCAPrivateKey returns the CA private key used by this store
func (s *GeneratedStore) GetCAPrivateKey() *ecdsa.PrivateKey {
	return s.caKey
}

// NewGeneratedStore creates a new store for auto-generated certificates
func NewGeneratedStore(opts GeneratedOptions) (*GeneratedStore, error) {
	var caKey *ecdsa.PrivateKey
	var caCert *x509.Certificate
	var err error

	if opts.CAKey != nil && opts.CACertificate != nil {
		caKey = opts.CAKey
		caCert = opts.CACertificate
	} else {
		// Generate CA key and certificate
		caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA key: %w", err)
		}

		caCert, err = generateCACertificate(caKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
		}
	}

	return &GeneratedStore{
		cache:         make(map[string]*cachedCert),
		cacheDuration: opts.CacheDuration,
		defaultTTL:    opts.DefaultTTL,
		caKey:         caKey,
		caCert:        caCert,
	}, nil
}

func (s *GeneratedStore) GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	// Check cache first
	s.cacheMu.RLock()
	if cached, ok := s.cache[serverName]; ok {
		if time.Now().Before(cached.expiresAt) {
			s.cacheMu.RUnlock()
			return cached.cert, nil
		}
	}
	s.cacheMu.RUnlock()

	// Generate new certificate
	cert, err := s.generateCertificate(serverName)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	s.cacheMu.Lock()
	s.cache[serverName] = &cachedCert{
		cert:      cert,
		expiresAt: time.Now().Add(s.cacheDuration),
	}
	s.cacheMu.Unlock()

	return cert, nil
}

func (s *GeneratedStore) PutCertificate(ctx context.Context, serverName string, cert *tls.Certificate) error {
	s.cacheMu.Lock()
	s.cache[serverName] = &cachedCert{
		cert:      cert,
		expiresAt: time.Now().Add(s.cacheDuration),
	}
	s.cacheMu.Unlock()
	return nil
}

func (s *GeneratedStore) RemoveCertificate(ctx context.Context, serverName string) error {
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

func (s *GeneratedStore) generateCertificate(serverName string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(s.defaultTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey: key,
		Leaf:       template,
	}

	return cert, nil
}

func generateCACertificate(key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ITP Generated CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:           0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return cert, nil
}
