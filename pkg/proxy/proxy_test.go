package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientSNI = "test-client"
	testServerSNI = "test-server"
	testEchoSNI   = "test-upstream"
)

// mockAddr implements net.Addr for testing
type mockAddr struct {
	network, address string
}

func (m mockAddr) Network() string { return m.network }
func (m mockAddr) String() string  { return m.address }

// mockConn implements a minimal net.Conn for testing getDefaultSNI
type mockConn struct {
	net.Conn
	addr net.Addr
}

func (m mockConn) LocalAddr() net.Addr { return m.addr }

func TestGetDefaultSNI(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{
			name:     "localhost IPv4",
			addr:     "127.0.0.1:8443",
			expected: "localhost",
		},
		{
			name:     "localhost IPv6",
			addr:     "[::1]:8443",
			expected: "localhost",
		},
		{
			name:     "any IPv4",
			addr:     "0.0.0.0:8443",
			expected: "localhost",
		},
		{
			name:     "any IPv6",
			addr:     "[::]:8443",
			expected: "localhost",
		},
		{
			name:     "specific IP",
			addr:     "192.168.1.1:8443",
			expected: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{addr: mockAddr{network: "tcp", address: tt.addr}}
			result := (&Proxy{}).getDefaultSNI(conn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNew(t *testing.T) {
	config := Config{
		CertStoreType:         "auto",
		CertStoreTTL:          24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		AllowUnknownCerts:     true,
		AutoMapCN:             true,
		ListenAddr:            ":8443",
	}

	p, err := New(config)
	require.NoError(t, err)

	assert.NotNil(t, p)
	assert.NotNil(t, p.router)
	assert.NotNil(t, p.translator)
	assert.NotNil(t, p.certStore)
	assert.Equal(t, config.AllowUnknownCerts, p.allowUnknownCerts)
	assert.True(t, p.AutoMapEnabled())
}

func TestHandleConnection(t *testing.T) {
	// Create test configuration
	config := Config{
		CertFile:              "auto",
		KeyFile:               "auto",
		CAFile:                "",
		CertStoreType:         "auto",
		CertStoreTTL:          24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		AllowUnknownCerts:     true,
		AutoMapCN:             false,
		ListenAddr:            "127.0.0.1:8443", // Use random port
		EchoName:              testEchoSNI, // Use echo server as the upstream
		EchoAddr:              "127.0.0.1:9443",
	}

	// Initialize proxy
	p, err := New(config)
	require.NoError(t, err)

	// Start proxy server in goroutine
	go func() {
		err := p.ListenAndServe(config)
		if err != nil {
			t.Errorf("proxy server failed: %v", err)
		}
	}()

	// Wait a bit for server to start
	time.Sleep(500 * time.Millisecond)

	// Create client connection
	clientConn, err := net.Dial("tcp", config.ListenAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Configure client TLS
	clientCert, err := p.certStore.GetCertificate(context.Background(), testClientSNI)
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		InsecureSkipVerify: true,
		ServerName:         testServerSNI,
	}

	// Create TLS connection
	clientTLSConn := tls.Client(clientConn, clientTLSConfig)
	defer clientTLSConn.Close()

	// Perform TLS handshake
	err = clientTLSConn.Handshake()
	require.NoError(t, err)

	// Write test request
	req, err := http.NewRequest(http.MethodGet, "https://"+testServerSNI, nil)
	require.NoError(t, err)

	err = req.Write(clientTLSConn)
	require.NoError(t, err)

	// Read response with timeout
	clientTLSConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), nil)
	require.NoError(t, err)

	// Check status code
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check headers
	assert.Equal(t, testClientSNI, resp.Header.Get("X-Client-CN"))
}

func TestHeaderInjection(t *testing.T) {
	// Create test configuration
	config := Config{
		CertFile:              "auto",
		KeyFile:               "auto",
		CAFile:                "",
		CertStoreType:         "auto",
		CertStoreTTL:          24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		AllowUnknownCerts:     true,
		AutoMapCN:             false,
		ListenAddr:            "127.0.0.1:8444", // Use random port
		EchoName:              testEchoSNI,      // Use echo server as the upstream
		EchoAddr:              "127.0.0.1:9444",
	}

	// Initialize proxy
	p, err := New(config)
	require.NoError(t, err)

	// Add header templates
	err = p.AddHeader(testEchoSNI, "X-Custom", "{{ .CommonName }}")
	require.NoError(t, err)

	err = p.AddCommonHeader("cn", testEchoSNI, "X-Common-CN")
	require.NoError(t, err)

	// Start proxy server in goroutine
	go func() {
		err := p.ListenAndServe(config)
		if err != nil {
			t.Errorf("proxy server failed: %v", err)
		}
	}()

	// Wait a bit for server to start
	time.Sleep(500 * time.Millisecond)

	// Create client connection
	clientConn, err := net.Dial("tcp", config.ListenAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Configure client TLS
	clientCert, err := p.certStore.GetCertificate(context.Background(), testClientSNI)
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		InsecureSkipVerify: true,
		ServerName:         testEchoSNI,
	}

	// Create TLS connection
	clientTLSConn := tls.Client(clientConn, clientTLSConfig)
	defer clientTLSConn.Close()

	// Perform TLS handshake
	err = clientTLSConn.Handshake()
	require.NoError(t, err)

	// Write test request
	req, err := http.NewRequest(http.MethodGet, "https://"+testEchoSNI, nil)
	require.NoError(t, err)

	err = req.Write(clientTLSConn)
	require.NoError(t, err)

	// Read response with timeout
	clientTLSConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), nil)
	require.NoError(t, err)

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check headers were properly injected
	assert.Equal(t, testClientSNI, resp.Header.Get("X-Custom"))
	assert.Equal(t, testClientSNI, resp.Header.Get("X-Common-CN"))
}
