package echo

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	cert := &tls.Certificate{}
	name := "echo.test"
	
	server := New(cert, name)
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
		id       uint16
		expected string
	}{
		{
			name:     "Known Cipher Suite",
			id:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			expected: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		},
		{
			name:     "Unknown Cipher Suite",
			id:       0xFFFF,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getCipherSuiteName(tt.id)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConnectionInfo(t *testing.T) {
	info := ConnectionInfo{
		RemoteAddr: "127.0.0.1:12345",
		LocalAddr:  "127.0.0.1:443",
		TLS: TLSInfo{
			Version:             "TLS_1.3",
			CipherSuite:        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			ServerName:         "example.com",
			NegotiatedProtocol: "h2",
			ClientCertProvided: true,
			ClientCertSubject:  "CN=client",
			ClientCertIssuer:   "CN=ca",
			ClientCertNotBefore: time.Now().Format(time.RFC3339),
			ClientCertNotAfter:  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		},
		Route: RouteInfo{
			UpstreamName: "test-upstream",
		},
	}

	assert.Equal(t, "127.0.0.1:12345", info.RemoteAddr)
	assert.Equal(t, "127.0.0.1:443", info.LocalAddr)
	assert.Equal(t, "TLS_1.3", info.TLS.Version)
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", info.TLS.CipherSuite)
	assert.Equal(t, "example.com", info.TLS.ServerName)
	assert.Equal(t, "h2", info.TLS.NegotiatedProtocol)
	assert.True(t, info.TLS.ClientCertProvided)
	assert.Equal(t, "CN=client", info.TLS.ClientCertSubject)
	assert.Equal(t, "CN=ca", info.TLS.ClientCertIssuer)
	assert.Equal(t, "test-upstream", info.Route.UpstreamName)
}
