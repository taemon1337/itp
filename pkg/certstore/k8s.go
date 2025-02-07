package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// K8sStore implements Store interface using Kubernetes TLS secrets and cert-manager Certificates
type K8sStore struct {
	client        kubernetes.Interface
	cmClient      cmclient.Interface
	namespace     string
	secretName    string
	cache         map[string]*cachedCert
	cacheMu       sync.RWMutex
	cacheDuration time.Duration
	defaultOpts   CertificateOptions
	issuerRef     cmmeta.ObjectReference // Reference to the cert-manager issuer
}

// K8sOptions contains Kubernetes-specific store options
type K8sOptions struct {
	StoreOptions
	Namespace   string
	Client      kubernetes.Interface
	CMClient    cmclient.Interface
	CACertPEM   []byte // Optional: CA certificate in PEM format
	IssuerName  string // Name of the cert-manager issuer to use
	IssuerKind  string // Kind of the cert-manager issuer (e.g., "ClusterIssuer" or "Issuer")
	IssuerGroup string // API group of the issuer (defaults to cert-manager.io)
}

// NewK8sStore creates a new Kubernetes-based certificate store
func NewK8sStore(opts K8sOptions) *K8sStore {
	if opts.IssuerGroup == "" {
		opts.IssuerGroup = "cert-manager.io"
	}

	return &K8sStore{
		client:        opts.Client,
		cmClient:      opts.CMClient,
		namespace:     opts.Namespace,
		cache:         make(map[string]*cachedCert),
		cacheDuration: opts.CacheDuration,
		defaultOpts: CertificateOptions{
			CommonName:  "", // Will be set per certificate
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		},
		issuerRef: cmmeta.ObjectReference{
			Name:  opts.IssuerName,
			Kind:  opts.IssuerKind,
			Group: opts.IssuerGroup,
		},
	}
}

func (s *K8sStore) GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	return s.GetCertificateWithOptions(ctx, serverName, s.defaultOpts)
}

func (s *K8sStore) GetCertificateWithOptions(ctx context.Context, serverName string, opts CertificateOptions) (*tls.Certificate, error) {
	// Check cache first
	s.cacheMu.RLock()
	if cached, ok := s.cache[serverName]; ok {
		if time.Now().Before(cached.expiresAt) {
			s.cacheMu.RUnlock()
			return cached.cert, nil
		}
	}
	s.cacheMu.RUnlock()

	// Try to get existing secret
	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, serverName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get secret %s: %w", serverName, err)
		}

		// Secret doesn't exist, create or update Certificate resource
		if err := s.createOrUpdateCertificate(ctx, serverName, opts); err != nil {
			return nil, fmt.Errorf("failed to create/update certificate: %w", err)
		}

		// Wait for the certificate to be ready
		if err := s.waitForCertificate(ctx, serverName); err != nil {
			return nil, fmt.Errorf("timeout waiting for certificate: %w", err)
		}

		// Get the newly created secret
		secret, err = s.client.CoreV1().Secrets(s.namespace).Get(ctx, serverName, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get created secret %s: %w", serverName, err)
		}
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

// createOrUpdateCertificate creates or updates a cert-manager Certificate resource
func (s *K8sStore) createOrUpdateCertificate(ctx context.Context, serverName string, opts CertificateOptions) error {
	usages := []cmapi.KeyUsage{}
	if opts.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, cmapi.UsageKeyEncipherment)
	}
	if opts.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, cmapi.UsageDigitalSignature)
	}
	if opts.KeyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, cmapi.UsageCertSign)
	}

	for _, usage := range opts.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, cmapi.UsageServerAuth)
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, cmapi.UsageClientAuth)
		}
	}

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverName,
			Namespace: s.namespace,
		},
		Spec: cmapi.CertificateSpec{
			SecretName: serverName,
			CommonName: serverName,
			Duration:   &metav1.Duration{Duration: opts.TTL},
			RenewBefore: &metav1.Duration{Duration: 24 * time.Hour}, // Renew 24h before expiry
			IssuerRef:  s.issuerRef,
			Usages:     usages,
			PrivateKey: &cmapi.CertificatePrivateKey{
				Algorithm: cmapi.RSAKeyAlgorithm,
				Size:      2048,
			},
		},
	}

	// Add DNS names if specified
	if len(opts.DNSNames) > 0 {
		cert.Spec.DNSNames = opts.DNSNames
	}

	// Add IP addresses if specified
	if len(opts.IPAddresses) > 0 {
		ipStrings := make([]string, len(opts.IPAddresses))
		for i, ip := range opts.IPAddresses {
			ipStrings[i] = ip.String()
		}
		cert.Spec.IPAddresses = ipStrings
	}

	// Try to get existing certificate
	existing, err := s.cmClient.CertmanagerV1().Certificates(s.namespace).Get(ctx, serverName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get certificate: %w", err)
		}
		// Create new certificate
		_, err = s.cmClient.CertmanagerV1().Certificates(s.namespace).Create(ctx, cert, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}
	} else {
		// Update existing certificate
		existing.Spec = cert.Spec
		_, err = s.cmClient.CertmanagerV1().Certificates(s.namespace).Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update certificate: %w", err)
		}
	}

	return nil
}

// waitForCertificate waits for the certificate to be ready
func (s *K8sStore) waitForCertificate(ctx context.Context, name string) error {
	return wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		cert, err := s.cmClient.CertmanagerV1().Certificates(s.namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		for _, cond := range cert.Status.Conditions {
			if cond.Type == cmapi.CertificateConditionReady {
				return cond.Status == cmmeta.ConditionTrue, nil
			}
		}

		return false, nil
	})
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
