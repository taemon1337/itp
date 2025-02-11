package certstore

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

	"github.com/itp/pkg/logger"
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
	logger        *logger.Logger
	caCertPool    *x509.CertPool    // Pool of CA certificates for verifying peers
	caCert        *x509.Certificate // The CA certificate used by this store
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
	log := logger.New("certstore", logger.LevelInfo)

	// Create cert pool and add any provided CA certs
	pool := x509.NewCertPool()
	if len(opts.CACertPEM) > 0 {
		log.Debug("Attempting to load provided CA certificate (len: %d bytes)", len(opts.CACertPEM))
		if ok := pool.AppendCertsFromPEM(opts.CACertPEM); !ok {
			log.Error("Failed to append provided CA certificate to pool - invalid PEM data")
		} else {
			// Parse the certificate to get details
			block, _ := pem.Decode(opts.CACertPEM)
			if block == nil {
				log.Error("Failed to decode PEM data for provided CA certificate")
			} else {
				certs, err := x509.ParseCertificates(block.Bytes)
				if err != nil {
					log.Error("Failed to parse provided CA certificate: %v", err)
				} else {
					for i, cert := range certs {
						log.Info("Loaded provided CA certificate %d: CN=%s, Issuer=%s", i, cert.Subject.CommonName, cert.Issuer.CommonName)
					}
				}
			}
		}
	} else {
		log.Debug("No CA certificate provided in options")
	}

	// If using cert-manager, try to get the cluster issuer CA
	if opts.CMClient != nil && opts.IssuerKind == "ClusterIssuer" {
		log.Debug("Attempting to load CA from cluster issuer %s", opts.IssuerName)
		clusterIssuer, err := opts.CMClient.CertmanagerV1().ClusterIssuers().Get(context.Background(), opts.IssuerName, metav1.GetOptions{})
		if err != nil {
			log.Error("Failed to get cluster issuer %s: %v", opts.IssuerName, err)
		} else {
			// Try to get CA from cluster issuer
			if clusterIssuer.Spec.CA == nil {
				log.Error("Cluster issuer %s does not have CA configuration", opts.IssuerName)
			} else if clusterIssuer.Spec.CA.SecretName == "" {
				log.Error("Cluster issuer %s CA configuration does not specify a secret", opts.IssuerName)
			} else {
				log.Debug("Found CA secret name %s for cluster issuer %s", clusterIssuer.Spec.CA.SecretName, opts.IssuerName)
				secret, err := opts.Client.CoreV1().Secrets("cert-manager").Get(context.Background(), clusterIssuer.Spec.CA.SecretName, metav1.GetOptions{})
				if err != nil {
					log.Error("Failed to get CA secret %s: %v", clusterIssuer.Spec.CA.SecretName, err)
				} else {
					caCert, ok := secret.Data["tls.crt"]
					if !ok {
						log.Error("CA secret %s does not contain tls.crt", clusterIssuer.Spec.CA.SecretName)
					} else {
						log.Debug("Found CA certificate in secret %s (len: %d bytes)", clusterIssuer.Spec.CA.SecretName, len(caCert))
						if ok := pool.AppendCertsFromPEM(caCert); !ok {
							log.Error("Failed to append cluster issuer CA certificate to pool - invalid PEM data")
						} else {
							// Parse the certificate to get details
							block, _ := pem.Decode(caCert)
							if block == nil {
								log.Error("Failed to decode PEM data for cluster issuer CA certificate")
							} else {
								certs, err := x509.ParseCertificates(block.Bytes)
								if err != nil {
									log.Error("Failed to parse cluster issuer CA certificate: %v", err)
								} else {
									for i, cert := range certs {
										log.Info("Loaded cluster issuer CA certificate %d: CN=%s, Issuer=%s", i, cert.Subject.CommonName, cert.Issuer.CommonName)
									}
								}
							}
						}
					}
				}
			}
		}
	} else {
		log.Debug("Not using cert-manager or not using ClusterIssuer - skipping cluster issuer CA lookup")
	}

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
		logger:     log,
		caCertPool: pool, // Add the CA pool we created
	}
}

func (s *K8sStore) GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	return s.GetCertificateWithOptions(ctx, serverName, &s.defaultOpts)
}

func (s *K8sStore) GetCertificateWithOptions(ctx context.Context, serverName string, opts *CertificateOptions) (*tls.Certificate, error) {
	s.logger.Debug("Getting certificate for server %s", serverName)
	// Check cache first
	s.cacheMu.RLock()
	if cached, ok := s.cache[serverName]; ok {
		if time.Now().Before(cached.expiresAt) {
			s.cacheMu.RUnlock()
			s.logger.Debug("Using cached certificate for server %s", serverName)
			return cached.cert, nil
		}
	}
	s.cacheMu.RUnlock()

	// Try to get existing secret from any namespace if namespace is empty
	s.logger.Debug("Attempting to get secret for server %s", serverName)
	var secret *corev1.Secret
	var err error
	if s.namespace == "" {
		// List secrets across all namespaces
		secrets, err := s.client.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
			FieldSelector: fmt.Sprintf("metadata.name=%s", serverName),
		})
		if err != nil {
			s.logger.Error("Failed to list secrets: %v", err)
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}
		// Use the first matching secret
		if len(secrets.Items) > 0 {
			secret = &secrets.Items[0]
		}
	} else {
		// Get secret from specific namespace
		secret, err = s.client.CoreV1().Secrets(s.namespace).Get(ctx, serverName, metav1.GetOptions{})
	}

	if err != nil || secret == nil {
		if err != nil && !errors.IsNotFound(err) {
			s.logger.Error("Failed to get secret %s: %v", serverName, err)
			return nil, fmt.Errorf("failed to get secret %s: %w", serverName, err)
		}

		// Determine namespace for new certificate
		targetNamespace := s.namespace
		if targetNamespace == "" {
			// Use default namespace if none specified
			targetNamespace = "default"
		}

		// Secret doesn't exist, create or update Certificate resource
		s.logger.Info("Secret not found for %s, creating new certificate in namespace %s", serverName, targetNamespace)
		if err := s.createOrUpdateCertificate(ctx, serverName, targetNamespace, *opts); err != nil {
			return nil, fmt.Errorf("failed to create/update certificate: %w", err)
		}

		// Wait for the certificate to be ready
		if err := s.waitForCertificate(ctx, serverName, targetNamespace); err != nil {
			return nil, fmt.Errorf("timeout waiting for certificate: %w", err)
		}

		// Get the newly created secret
		secret, err = s.client.CoreV1().Secrets(targetNamespace).Get(ctx, serverName, metav1.GetOptions{})
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
func (s *K8sStore) createOrUpdateCertificate(ctx context.Context, serverName string, namespace string, opts CertificateOptions) error {
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

	// Ensure minimum duration is at least 1 hour
	duration := opts.TTL
	if duration < time.Hour {
		duration = 24 * time.Hour // Default to 24 hours if not specified
	}

	// Ensure renewBefore is at least 5 minutes and less than duration
	renewBefore := duration / 3 // Default to 1/3 of duration
	if renewBefore < 5*time.Minute {
		renewBefore = 5 * time.Minute
	}
	if renewBefore >= duration {
		renewBefore = duration / 2
	}

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serverName,
			Namespace: namespace,
		},
		Spec: cmapi.CertificateSpec{
			SecretName: serverName,
			CommonName: serverName,
			Duration:   &metav1.Duration{Duration: duration},
			RenewBefore: &metav1.Duration{Duration: renewBefore},
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
	s.logger.Debug("Checking for existing certificate %s in namespace %s", serverName, namespace)
	existing, err := s.cmClient.CertmanagerV1().Certificates(namespace).Get(ctx, serverName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get certificate: %w", err)
		}
		// Create new certificate
		s.logger.Info("Creating new certificate %s in namespace %s", serverName, namespace)
		_, err = s.cmClient.CertmanagerV1().Certificates(namespace).Create(ctx, cert, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}
	} else {
		// Update existing certificate
		s.logger.Info("Updating existing certificate %s in namespace %s", serverName, namespace)
		existing.Spec = cert.Spec
		_, err = s.cmClient.CertmanagerV1().Certificates(namespace).Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update certificate: %w", err)
		}
	}

	return nil
}

// waitForCertificate waits for the certificate to be ready
func (s *K8sStore) waitForCertificate(ctx context.Context, name string, namespace string) error {
	return wait.PollImmediate(time.Second, 30*time.Second, func() (bool, error) {
		cert, err := s.cmClient.CertmanagerV1().Certificates(namespace).Get(ctx, name, metav1.GetOptions{})
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
	if s.caCertPool == nil {
		s.caCertPool = x509.NewCertPool()
	}
	return s.caCertPool
}

// GetCACertificate returns the CA certificate used by this store
func (s *K8sStore) GetCACertificate() *x509.Certificate {
	return s.caCert
}

// GetCAPrivateKey returns the CA private key used by this store
func (s *K8sStore) GetCAPrivateKey() *rsa.PrivateKey {
	return nil // K8s store doesn't manage CA keys directly
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
