package certstore

import (
	"context"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmfake "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/require"
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
		StoreOptions: StoreOptions{
			DefaultTTL: time.Hour,
			CacheDuration: time.Minute,
		},
		Namespace:   "test-ns",
		Client:      k8sClient,
		CMClient:    cmClient,
		IssuerName:  "test-issuer",
		IssuerKind:  "ClusterIssuer",
		IssuerGroup: "cert-manager.io",
	})

	require.NotNil(t, store)
	require.Equal(t, "test-ns", store.namespace)
}

// Minimal test to check if it's the cert-manager fake client causing issues
func TestMinimalCertStore(t *testing.T) {
	k8sClient := fake.NewSimpleClientset()
	cmClient := cmfake.NewSimpleClientset()

	// Mock cert-manager get certificates to return not found
	cmClient.PrependReactor("get", "certificates",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.NewNotFound(schema.GroupResource{Resource: "certificates"}, "test-cert")
		})

	// Mock cert-manager create certificates to return ready certificate
	cmClient.PrependReactor("create", "certificates",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			cert := &cmapi.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cert",
					Namespace: "test-ns",
				},
				Status: cmapi.CertificateStatus{
					Conditions: []cmapi.CertificateCondition{
						{
							Type:   cmapi.CertificateConditionReady,
							Status: cmmeta.ConditionTrue,
						},
					},
				},
			}
			return true, cert, nil
		})

	store := NewK8sStore(K8sOptions{
		StoreOptions: StoreOptions{
			DefaultTTL: time.Hour,
			CacheDuration: time.Minute,
		},
		Namespace:   "test-ns",
		Client:      k8sClient,
		CMClient:    cmClient,
		IssuerName:  "test-issuer",
		IssuerKind:  "ClusterIssuer",
		IssuerGroup: "cert-manager.io",
	})

	// Just try to get a non-existent certificate
	_, err := store.GetCertificate(context.Background(), "test-cert")
	require.Error(t, err)
}
