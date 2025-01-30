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

// CertificateOptions contains options for creating a certificate
type CertificateOptions struct {
	CommonName    string
	TTL          time.Duration
	CacheDuration time.Duration
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	IPAddresses  []net.IP // Optional: IP addresses to include as SANs
	DNSNames     []string // Optional: DNS names to include as SANs
}

// StoreOptions contains options for creating a new certificate store
type StoreOptions struct {
	CommonName    string
	TTL          time.Duration
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
	CAKey        *rsa.PrivateKey  // Optional: existing CA private key
	CACert       *x509.Certificate // Optional: existing CA certificate
	CacheDuration time.Duration
}

// DefaultCertificateOptions returns the default options for certificate generation
func DefaultCertificateOptions() CertificateOptions {
	return CertificateOptions{
		CommonName:    "Default CA",
		TTL:          24 * time.Hour,
		CacheDuration: time.Hour,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

// DefaultStoreOptions returns the default options for creating a new certificate store
func DefaultStoreOptions() StoreOptions {
	return StoreOptions{
		CommonName:    "Default CA",
		TTL:          24 * time.Hour,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CacheDuration: time.Hour,
	}
}

// GeneratedStore is a certificate store that generates certificates on demand
type GeneratedStore struct {
	mu            sync.RWMutex
	cache         map[string]*tls.Certificate
	ca            *x509.Certificate
	caKey         *rsa.PrivateKey
	defaultOpts   StoreOptions
	cacheDuration time.Duration
}

// NewGeneratedStore creates a new store for auto-generated certificates
func NewGeneratedStore(opts StoreOptions) (*GeneratedStore, error) {
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
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %v", err)
		}

		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: opts.CommonName,
			},
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(opts.TTL + time.Minute),
			KeyUsage:             x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                 true,
			MaxPathLen:           1,
		}

		caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create CA certificate: %v", err)
		}

		caCert, err = x509.ParseCertificate(caCertDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
		}
	}

	return &GeneratedStore{
		cache:         make(map[string]*tls.Certificate),
		ca:            caCert,
		caKey:         caKey,
		defaultOpts:   opts,
		cacheDuration: opts.CacheDuration,
	}, nil
}

func (s *GeneratedStore) generateCertificate(serverName string, opts CertificateOptions) (*tls.Certificate, error) {
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
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(opts.TTL + time.Minute),
		KeyUsage:             opts.KeyUsage,
		ExtKeyUsage:          opts.ExtKeyUsage,
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

	// Add IP addresses from CertificateOptions
	template.IPAddresses = append(template.IPAddresses, opts.IPAddresses...)

	// Add DNS names from CertificateOptions
	template.DNSNames = append(template.DNSNames, opts.DNSNames...)

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
	return s.GetCertificateWithOptions(ctx, serverName, DefaultCertificateOptions())
}

// GetCertificateWithOptions gets or generates a certificate for the given server name with specific options
func (s *GeneratedStore) GetCertificateWithOptions(ctx context.Context, serverName string, opts CertificateOptions) (*tls.Certificate, error) {
	s.mu.RLock()
	if cert, ok := s.cache[serverName]; ok {
		s.mu.RUnlock()
		return cert, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check again in case another goroutine generated it
	if cert, ok := s.cache[serverName]; ok {
		return cert, nil
	}

	// Generate new certificate
	cert, err := s.generateCertificate(serverName, opts)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	s.cache[serverName] = cert

	return cert, nil
}

func (s *GeneratedStore) PutCertificate(ctx context.Context, serverName string, cert *tls.Certificate) error {
	s.mu.Lock()
	s.cache[serverName] = cert
	s.mu.Unlock()
	return nil
}

func (s *GeneratedStore) RemoveCertificate(ctx context.Context, serverName string) error {
	s.mu.Lock()
	delete(s.cache, serverName)
	s.mu.Unlock()
	return nil
}

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

// TLSClientOptions contains options for creating a TLS client configuration
type TLSClientOptions struct {
	ServerName string // Required: server name for certificate verification
	InsecureSkipVerify bool // Optional: skip certificate verification (not recommended)
}

// TLSServerOptions contains options for creating a TLS server configuration
type TLSServerOptions struct {
	ClientAuth tls.ClientAuthType // Optional: defaults to RequireAndVerifyClientCert
	ClientCAs  *x509.CertPool    // Optional: custom cert pool for client verification
}

// GetTLSClientConfig returns a TLS configuration suitable for a client
func (s *GeneratedStore) GetTLSClientConfig(cert *tls.Certificate, opts TLSClientOptions) *tls.Config {
	if opts.ServerName == "" {
		// Use cert's common name as server name if not specified
		if cert != nil && cert.Leaf != nil {
			opts.ServerName = cert.Leaf.Subject.CommonName
		}
	}
	
	config := &tls.Config{
		RootCAs:            s.GetCertPool(),
		ServerName:         opts.ServerName,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	
	return config
}

// GetTLSServerConfig returns a TLS configuration suitable for a server
func (s *GeneratedStore) GetTLSServerConfig(cert *tls.Certificate, opts TLSServerOptions) *tls.Config {
	if opts.ClientAuth == tls.ClientAuthType(0) {
		opts.ClientAuth = tls.RequireAndVerifyClientCert
	}
	
	config := &tls.Config{
		ClientCAs:  opts.ClientCAs,
		ClientAuth: opts.ClientAuth,
	}
	
	if config.ClientCAs == nil {
		config.ClientCAs = s.GetCertPool()
	}
	
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	
	return config
}
