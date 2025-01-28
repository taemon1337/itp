package certstore

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStore implements the Store interface for testing
type MockStore struct {
	mock.Mock
}

func (m *MockStore) GetCertificate(ctx context.Context, serverName string) (*tls.Certificate, error) {
	args := m.Called(ctx, serverName)
	if cert := args.Get(0); cert != nil {
		return cert.(*tls.Certificate), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStore) PutCertificate(ctx context.Context, serverName string, cert *tls.Certificate) error {
	args := m.Called(ctx, serverName, cert)
	return args.Error(0)
}

func (m *MockStore) RemoveCertificate(ctx context.Context, serverName string) error {
	args := m.Called(ctx, serverName)
	return args.Error(0)
}

func (m *MockStore) GetCertificateExpiry(ctx context.Context, serverName string) (time.Time, error) {
	args := m.Called(ctx, serverName)
	return args.Get(0).(time.Time), args.Error(1)
}

func TestOptions(t *testing.T) {
	opts := Options{
		CacheDuration: 1 * time.Hour,
		DefaultTTL:    24 * time.Hour,
	}

	assert.Equal(t, 1*time.Hour, opts.CacheDuration)
	assert.Equal(t, 24*time.Hour, opts.DefaultTTL)
}

func TestCachedCert(t *testing.T) {
	cert := &tls.Certificate{}
	expiry := time.Now().Add(1 * time.Hour)
	
	cached := &cachedCert{
		cert:      cert,
		expiresAt: expiry,
	}

	assert.Equal(t, cert, cached.cert)
	assert.Equal(t, expiry, cached.expiresAt)
}

// Example usage of MockStore
func TestMockStoreUsage(t *testing.T) {
	store := new(MockStore)
	ctx := context.Background()
	serverName := "example.com"
	cert := &tls.Certificate{}
	expiry := time.Now().Add(1 * time.Hour)

	// Setup expectations
	store.On("GetCertificate", ctx, serverName).Return(cert, nil)
	store.On("PutCertificate", ctx, serverName, cert).Return(nil)
	store.On("RemoveCertificate", ctx, serverName).Return(nil)
	store.On("GetCertificateExpiry", ctx, serverName).Return(expiry, nil)

	// Test GetCertificate
	resultCert, err := store.GetCertificate(ctx, serverName)
	assert.NoError(t, err)
	assert.Equal(t, cert, resultCert)

	// Test PutCertificate
	err = store.PutCertificate(ctx, serverName, cert)
	assert.NoError(t, err)

	// Test RemoveCertificate
	err = store.RemoveCertificate(ctx, serverName)
	assert.NoError(t, err)

	// Test GetCertificateExpiry
	resultExpiry, err := store.GetCertificateExpiry(ctx, serverName)
	assert.NoError(t, err)
	assert.Equal(t, expiry, resultExpiry)

	// Verify all expectations were met
	store.AssertExpectations(t)
}
