package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestNewK8sStore(t *testing.T) {
	k8sClient := fake.NewSimpleClientset()
	cmClient := cmfake.NewSimpleClientset()

	store := NewK8sStore(K8sOptions{
		Options: Options{
			DefaultTTL:    time.Hour,
			CacheDuration: time.Minute,
		},
		Namespace:   "test-ns",
		Client:      k8sClient,
		CMClient:    cmClient,
		IssuerName:  "test-issuer",
		IssuerKind:  "ClusterIssuer",
		IssuerGroup: "cert-manager.io",
	})

	assert.NotNil(t, store)
	assert.Equal(t, "test-ns", store.namespace)
	assert.Equal(t, time.Hour, store.defaultOpts.TTL)
	assert.Equal(t, time.Minute, store.cacheDuration)
	assert.Equal(t, "test-issuer", store.issuerRef.Name)
	assert.Equal(t, "ClusterIssuer", store.issuerRef.Kind)
	assert.Equal(t, "cert-manager.io", store.issuerRef.Group)
}

func TestGetCertificate(t *testing.T) {
	// Create test certificate and secret
	testCert := &tls.Certificate{}
	testSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cert",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("test-cert"),
			"tls.key": []byte("test-key"),
		},
		Type: corev1.SecretTypeTLS,
	}

	tests := []struct {
		name           string
		serverName     string
		setupMocks     func(k8s *fake.Clientset, cm *cmfake.Clientset)
		expectedError  string
		expectCertReq  bool
		expectSecretOp bool
	}{
		{
			name:       "existing secret returns certificate",
			serverName: "test-cert",
			setupMocks: func(k8s *fake.Clientset, cm *cmfake.Clientset) {
				k8s.CoreV1().Secrets("test-ns").Create(context.Background(), testSecret, metav1.CreateOptions{})
			},
			expectSecretOp: true,
		},
		{
			name:       "missing secret creates certificate",
			serverName: "new-cert",
			setupMocks: func(k8s *fake.Clientset, cm *cmfake.Clientset) {
				// Add reactor to simulate cert-manager creating the secret
				k8s.PrependReactor("get", "secrets",
					func(action ktesting.Action) (bool, runtime.Object, error) {
						getAction := action.(ktesting.GetAction)
						if getAction.GetName() == "new-cert" {
							// First call returns not found, subsequent calls return the secret
							if k8s.Actions()[0].GetResource().Resource != "secrets" {
								return true, testSecret, nil
							}
							return true, nil, errors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "new-cert")
						}
						return false, nil, nil
					})

				// Add reactor to simulate cert-manager creating certificate
				cm.PrependReactor("create", "certificates",
					func(action ktesting.Action) (bool, runtime.Object, error) {
						cert := action.(ktesting.CreateAction).GetObject().(*cmapi.Certificate)
						cert.Status.Conditions = []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionReady,
								Status: cmmeta.ConditionTrue,
							},
						}
						return true, cert, nil
					})
			},
			expectCertReq:  true,
			expectSecretOp: true,
		},
		{
			name:       "secret creation fails",
			serverName: "error-cert",
			setupMocks: func(k8s *fake.Clientset, cm *cmfake.Clientset) {
				k8s.PrependReactor("get", "secrets",
					func(action ktesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.NewInternalError(assert.AnError)
					})
			},
			expectedError:  "failed to get secret error-cert: Internal error occurred: assert.AnError general error for testing",
			expectSecretOp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh clients for each test
			k8sClient := fake.NewSimpleClientset()
			cmClient := cmfake.NewSimpleClientset()

			if tt.setupMocks != nil {
				tt.setupMocks(k8sClient, cmClient)
			}

			store := NewK8sStore(K8sOptions{
				Options: Options{
					DefaultTTL:    time.Hour,
					CacheDuration: time.Minute,
				},
				Namespace:   "test-ns",
				Client:      k8sClient,
				CMClient:    cmClient,
				IssuerName:  "test-issuer",
				IssuerKind:  "ClusterIssuer",
				IssuerGroup: "cert-manager.io",
			})

			cert, err := store.GetCertificate(context.Background(), tt.serverName)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, cert)

			// Verify expected operations occurred
			var certReqs, secretOps int
			for _, action := range cmClient.Actions() {
				if action.GetResource().Resource == "certificates" {
					certReqs++
				}
			}
			for _, action := range k8sClient.Actions() {
				if action.GetResource().Resource == "secrets" {
					secretOps++
				}
			}

			if tt.expectCertReq {
				assert.Greater(t, certReqs, 0, "expected certificate requests")
			}
			if tt.expectSecretOp {
				assert.Greater(t, secretOps, 0, "expected secret operations")
			}
		})
	}
}

func TestGetCertificateWithOptions(t *testing.T) {
	testSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cert",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("test-cert"),
			"tls.key": []byte("test-key"),
		},
		Type: corev1.SecretTypeTLS,
	}

	tests := []struct {
		name          string
		serverName    string
		options       CertificateOptions
		setupMocks    func(k8s *fake.Clientset, cm *cmfake.Clientset)
		expectedError string
		validateCert  func(t *testing.T, cert *cmapi.Certificate)
	}{
		{
			name:       "creates certificate with custom options",
			serverName: "custom-cert",
			options: CertificateOptions{
				TTL:         2 * time.Hour,
				KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    []string{"test.example.com"},
			},
			setupMocks: func(k8s *fake.Clientset, cm *cmfake.Clientset) {
				k8s.PrependReactor("get", "secrets",
					func(action ktesting.Action) (bool, runtime.Object, error) {
						getAction := action.(ktesting.GetAction)
						if getAction.GetName() == "custom-cert" {
							if k8s.Actions()[0].GetResource().Resource != "secrets" {
								return true, testSecret, nil
							}
							return true, nil, errors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "custom-cert")
						}
						return false, nil, nil
					})

				cm.PrependReactor("create", "certificates",
					func(action ktesting.Action) (bool, runtime.Object, error) {
						cert := action.(ktesting.CreateAction).GetObject().(*cmapi.Certificate)
						cert.Status.Conditions = []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionReady,
								Status: cmmeta.ConditionTrue,
							},
						}
						return true, cert, nil
					})
			},
			validateCert: func(t *testing.T, cert *cmapi.Certificate) {
				assert.Equal(t, "custom-cert", cert.Name)
				assert.Equal(t, "test-ns", cert.Namespace)
				assert.Equal(t, "custom-cert", cert.Spec.CommonName)
				assert.Equal(t, []string{"test.example.com"}, cert.Spec.DNSNames)
				assert.Equal(t, metav1.Duration{Duration: 2 * time.Hour}, *cert.Spec.Duration)
				assert.Contains(t, cert.Spec.Usages, cmapi.UsageKeyEncipherment)
				assert.Contains(t, cert.Spec.Usages, cmapi.UsageDigitalSignature)
				assert.Contains(t, cert.Spec.Usages, cmapi.UsageServerAuth)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset()
			cmClient := cmfake.NewSimpleClientset()

			if tt.setupMocks != nil {
				tt.setupMocks(k8sClient, cmClient)
			}

			store := NewK8sStore(K8sOptions{
				Options: Options{
					DefaultTTL:    time.Hour,
					CacheDuration: time.Minute,
				},
				Namespace:   "test-ns",
				Client:      k8sClient,
				CMClient:    cmClient,
				IssuerName:  "test-issuer",
				IssuerKind:  "ClusterIssuer",
				IssuerGroup: "cert-manager.io",
			})

			cert, err := store.GetCertificateWithOptions(context.Background(), tt.serverName, tt.options)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, cert)

			// Find and validate the created certificate if a validator was provided
			if tt.validateCert != nil {
				var createdCert *cmapi.Certificate
				for _, action := range cmClient.Actions() {
					if action.GetVerb() == "create" && action.GetResource().Resource == "certificates" {
						createdCert = action.(ktesting.CreateAction).GetObject().(*cmapi.Certificate)
						break
					}
				}
				require.NotNil(t, createdCert, "expected certificate to be created")
				tt.validateCert(t, createdCert)
			}
		})
	}
}

func TestCertificateCache(t *testing.T) {
	testSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cached-cert",
			Namespace: "test-ns",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("test-cert"),
			"tls.key": []byte("test-key"),
		},
		Type: corev1.SecretTypeTLS,
	}

	k8sClient := fake.NewSimpleClientset()
	cmClient := cmfake.NewSimpleClientset()

	// Add the test secret
	k8sClient.CoreV1().Secrets("test-ns").Create(context.Background(), testSecret, metav1.CreateOptions{})

	store := NewK8sStore(K8sOptions{
		Options: Options{
			DefaultTTL:    time.Hour,
			CacheDuration: time.Second * 2, // Short duration for testing
		},
		Namespace:   "test-ns",
		Client:      k8sClient,
		CMClient:    cmClient,
		IssuerName:  "test-issuer",
		IssuerKind:  "ClusterIssuer",
		IssuerGroup: "cert-manager.io",
	})

	// First request should hit the API
	cert1, err := store.GetCertificate(context.Background(), "cached-cert")
	require.NoError(t, err)
	assert.NotNil(t, cert1)
	assert.Equal(t, 1, len(k8sClient.Actions()))

	// Second request should use cache
	cert2, err := store.GetCertificate(context.Background(), "cached-cert")
	require.NoError(t, err)
	assert.NotNil(t, cert2)
	assert.Equal(t, 1, len(k8sClient.Actions()), "expected no additional API calls")

	// Wait for cache to expire
	time.Sleep(time.Second * 3)

	// Third request should hit the API again
	cert3, err := store.GetCertificate(context.Background(), "cached-cert")
	require.NoError(t, err)
	assert.NotNil(t, cert3)
	assert.Equal(t, 2, len(k8sClient.Actions()), "expected additional API call after cache expiry")
}
