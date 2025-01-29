package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// K8sStore implements Store interface using Kubernetes TLS secrets
type K8sStore struct {
	client        kubernetes.Interface
	namespace     string
	secretName    string
	cache         map[string]*cachedCert
	cacheMu       sync.RWMutex
	cacheDuration time.Duration
	defaultOpts   CertificateOptions
}

// K8sOptions contains Kubernetes-specific store options
type K8sOptions struct {
	Options
	Namespace  string
	Client     kubernetes.Interface
	CACertPEM []byte // Optional: CA certificate in PEM format
}

// NewK8sStore creates a new Kubernetes-based certificate store
func NewK8sStore(opts K8sOptions) *K8sStore {
	return &K8sStore{
		client:        opts.Client,
		namespace:     opts.Namespace,
		cache:        make(map[string]*cachedCert),
		cacheDuration: opts.CacheDuration,
		defaultOpts: CertificateOptions{
			TTL:         opts.DefaultTTL,
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		},
	}
}

func (s *K8sStore) GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	// Check cache first
	s.cacheMu.RLock()
	if cached, ok := s.cache[serverName]; ok {
		if time.Now().Before(cached.expiresAt) {
			s.cacheMu.RUnlock()
			return cached.cert, nil
		}
	}
	s.cacheMu.RUnlock()

	// Fetch from Kubernetes
	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, serverName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s: %w", serverName, err)
	}

	cert, err := s.parseTLSSecret(secret)
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

func (s *K8sStore) GetCertificateWithOptions(ctx context.Context, serverName string, opts CertificateOptions) (*tls.Certificate, error) {
	// K8s store doesn't support custom options, fallback to default GetCertificate
	return s.GetCertificate(ctx, serverName)
}

func (s *K8sStore) PutCertificate(ctx context.Context, serverName string, cert *tls.Certificate) error {
	// Not implemented for K8s store as certs are managed by cert-manager
	return fmt.Errorf("PutCertificate not supported for Kubernetes store")
}

func (s *K8sStore) RemoveCertificate(ctx context.Context, serverName string) error {
	s.cacheMu.Lock()
	delete(s.cache, serverName)
	s.cacheMu.Unlock()
	return nil
}

func (s *K8sStore) GetCertificateExpiry(ctx context.Context, serverName string) (time.Time, error) {
	cert, err := s.GetCertificate(ctx, serverName)
	if err != nil {
		return time.Time{}, err
	}
	return cert.Leaf.NotAfter, nil
}

func (s *K8sStore) GetCertPool() *x509.CertPool {
	return x509.NewCertPool() // Return empty pool as K8s store doesn't manage CA certs
}

func (s *K8sStore) GetTLSClientConfig(cert *tls.Certificate, opts TLSClientOptions) *tls.Config {
	if opts.ServerName == "" {
		// Use cert's common name as server name if not specified
		if cert != nil && cert.Leaf != nil {
			opts.ServerName = cert.Leaf.Subject.CommonName
		}
	}
	
	config := &tls.Config{
		ServerName:         opts.ServerName,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	
	return config
}

func (s *K8sStore) GetTLSServerConfig(cert *tls.Certificate, opts TLSServerOptions) *tls.Config {
	if opts.ClientAuth == tls.ClientAuthType(0) {
		opts.ClientAuth = tls.RequireAndVerifyClientCert
	}
	
	config := &tls.Config{
		ClientAuth: opts.ClientAuth,
	}
	
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	
	return config
}

func (s *K8sStore) parseTLSSecret(secret *corev1.Secret) (*tls.Certificate, error) {
	certBytes, ok := secret.Data["tls.crt"]
	if !ok {
		return nil, fmt.Errorf("tls.crt not found in secret")
	}

	keyBytes, ok := secret.Data["tls.key"]
	if !ok {
		return nil, fmt.Errorf("tls.key not found in secret")
	}

	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 key pair: %w", err)
	}

	return &cert, nil
}
