package certstore

import (
	"context"
	"crypto/tls"
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
	cache         map[string]*cachedCert
	cacheMu       sync.RWMutex
	cacheDuration time.Duration
}

type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// K8sOptions contains Kubernetes-specific store options
type K8sOptions struct {
	Options
	Namespace string
	Client    kubernetes.Interface
}

// NewK8sStore creates a new Kubernetes-based certificate store
func NewK8sStore(opts K8sOptions) *K8sStore {
	return &K8sStore{
		client:        opts.Client,
		namespace:     opts.Namespace,
		cache:        make(map[string]*cachedCert),
		cacheDuration: opts.CacheDuration,
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
