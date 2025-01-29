package echo

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/itp/pkg/logger"
)

// setupTestLogger creates a logger for testing
func setupTestLogger() *logger.Logger {
	return logger.New("echo", logger.LevelDebug)
}

func TestNew(t *testing.T) {
	cert := &tls.Certificate{}
	name := "echo.test"
	
	server := New(cert, nil, name)
	assert.NotNil(t, server)
	assert.Equal(t, cert, server.cert)
	assert.Equal(t, name, server.name)
}

func TestGetTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  uint16
		expected string
	}{
		{
			name:     "TLS 1.0",
			version:  tls.VersionTLS10,
			expected: "TLS_1.0",
		},
		{
			name:     "TLS 1.1",
			version:  tls.VersionTLS11,
			expected: "TLS_1.1",
		},
		{
			name:     "TLS 1.2",
			version:  tls.VersionTLS12,
			expected: "TLS_1.2",
		},
		{
			name:     "TLS 1.3",
			version:  tls.VersionTLS13,
			expected: "TLS_1.3",
		},
		{
			name:     "Unknown Version",
			version:  0xFFFF,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTLSVersion(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetCipherSuiteName(t *testing.T) {
	tests := []struct {
		name     string
		cipher   uint16
		expected string
	}{
		{
			name:     "Known Cipher",
			cipher:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			expected: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		{
			name:     "Unknown Cipher",
			cipher:   0xFFFF,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCipherSuiteName(tt.cipher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHandleConnection(t *testing.T) {
	// Create a mock TLS connection state
	state := tls.ConnectionState{
		Version:     tls.VersionTLS12,
		CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		ServerName:  "test.server",
	}

	// Test the TLS version and cipher suite functions directly
	version := getTLSVersion(state.Version)
	cipher := getCipherSuiteName(state.CipherSuite)

	assert.Equal(t, "TLS_1.2", version)
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", cipher)
	assert.Equal(t, "test.server", state.ServerName)
}
