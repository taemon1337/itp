package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/itp/pkg/logger"
	"github.com/itp/pkg/certstore"
)

const (
	testInternalDomain = "internal.local"
	testExternalDomain = "external.com"
	testClientSNI = "test-client"
	testServerSNI = "test-server"
	testEchoSNI   = "test-upstream"
	upstreamServerName = testEchoSNI + "." + testInternalDomain
)

// setupTestLoggers creates loggers for testing
func setupTestLoggers() (*logger.Logger, *logger.Logger, *logger.Logger, *logger.Logger) {
	proxyLogger := logger.New("proxy", logger.LevelDebug)
	routerLogger := logger.New("router", logger.LevelDebug)
	translatorLogger := logger.New("translator", logger.LevelDebug)
	echoLogger := logger.New("echo", logger.LevelDebug)
	return proxyLogger, routerLogger, translatorLogger, echoLogger
}

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
			proxyLogger, _, _, _ := setupTestLoggers()
			proxy := &Proxy{logger: proxyLogger}
			conn := &mockConn{addr: mockAddr{network: "tcp", address: tt.addr}}
			result := proxy.getDefaultSNI(conn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNew(t *testing.T) {
	proxyLogger, routerLogger, translatorLogger, echoLogger := setupTestLoggers()
	config := &Config{
		CertStoreType:         "auto",
		CertStoreTTL:          24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		AllowUnknownCerts:     true,
		AutoMapCN:             true,
		ListenAddr:            ":8443",
		ProxyLogger:          proxyLogger,
		RouterLogger:         routerLogger,
		TranslatorLogger:     translatorLogger,
		EchoLogger:          echoLogger,
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
	proxyLogger, routerLogger, translatorLogger, echoLogger := setupTestLoggers()
	// Create test configuration
	config := &Config{
		CertFile:              "auto",
		KeyFile:               "auto",
		CAFile:                "",
		ServerName:            testServerSNI,
		InternalDomain:        testInternalDomain,
		ExternalDomain:        testExternalDomain,
		CertOptions: certstore.CertificateOptions{
			DNSNames:              []string{fmt.Sprintf("*.%s", testInternalDomain)},
		},
		CertStoreType:         "auto",
		CertStoreTTL:          24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		AllowUnknownCerts:     true,
		AutoMapCN:             true, // Enable auto mapping
		ListenAddr:            "127.0.0.1:8443",
		EchoName:              testEchoSNI, // Use echo server as the upstream
		EchoAddr:              "127.0.0.1:9443",
		ProxyLogger:          proxyLogger,
		RouterLogger:         routerLogger,
		TranslatorLogger:     translatorLogger,
		EchoLogger:          echoLogger,
	}

	// Initialize proxy
	p, err := New(config)
	require.NoError(t, err)

	// Add static route for echo server
	p.AddStaticRoute(testEchoSNI, config.EchoAddr)

	// Add common headers
	err = p.AddCommonHeader("cn", upstreamServerName, "X-Client-CN")
	require.NoError(t, err)

	// Start echo server and proxy server in goroutine
	go func() {
		err := p.ListenAndServe(config)
		if err != nil {
			t.Errorf("proxy server failed: %v", err)
		}
	}()

	// Wait for both proxy and echo server to be ready
	require.NoError(t, waitForServer(t, config.ListenAddr))
	require.NoError(t, waitForServer(t, config.EchoAddr))

	// Create client connection
	clientConn, err := net.Dial("tcp", config.ListenAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Configure client TLS
	clientCert, err := p.certStore.GetCertificate(context.Background(), testClientSNI)
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		RootCAs:            p.certStore.GetCertPool(),
		ServerName:         upstreamServerName,
	}

	// Create TLS connection
	clientTLSConn := tls.Client(clientConn, clientTLSConfig)
	defer clientTLSConn.Close()

	// Perform TLS handshake
	err = clientTLSConn.Handshake()
	require.NoError(t, err)

	// Write test request
	req, err := http.NewRequest(http.MethodGet, "https://"+upstreamServerName, nil)
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
	proxyLogger, routerLogger, translatorLogger, echoLogger := setupTestLoggers()
	// Create test configuration
	config := &Config{
		CertFile:              "auto",
		KeyFile:               "auto",
		CAFile:                "",
		ServerName:            testServerSNI,
		InternalDomain:        testInternalDomain,
		ExternalDomain:        testExternalDomain,
		CertOptions: certstore.CertificateOptions{
			DNSNames:              []string{fmt.Sprintf("*.%s", testInternalDomain)},
		},
		CertStoreType:         "auto",
		CertStoreTTL:          24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		AllowUnknownCerts:     true,
		AutoMapCN:             true,
		ListenAddr:            "127.0.0.1:8444",
		EchoName:              testEchoSNI,
		EchoAddr:              "127.0.0.1:9444",
		ProxyLogger:          proxyLogger,
		RouterLogger:         routerLogger,
		TranslatorLogger:     translatorLogger,
		EchoLogger:          echoLogger,
	}

	// Initialize proxy
	p, err := New(config)
	require.NoError(t, err)

	// Add static route for echo server
	p.AddStaticRoute(testEchoSNI, config.EchoAddr)

	// Add header templates
	err = p.AddHeader(testEchoSNI, "X-Custom", "{{ .CommonName }}")
	require.NoError(t, err)

	err = p.AddCommonHeader("cn", upstreamServerName, "X-Common-CN")
	require.NoError(t, err)

	// Start echo server and proxy server in goroutine
	go func() {
		err := p.ListenAndServe(config)
		if err != nil {
			t.Errorf("proxy server failed: %v", err)
		}
	}()

	// Wait for both servers to be ready
	require.NoError(t, waitForServer(t, config.ListenAddr))
	require.NoError(t, waitForServer(t, config.EchoAddr))

	// Create client connection
	clientConn, err := net.Dial("tcp", config.ListenAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Configure client TLS
	clientCert, err := p.certStore.GetCertificate(context.Background(), testClientSNI)
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		RootCAs:            p.certStore.GetCertPool(),
		ServerName:         upstreamServerName,
	}

	// Create TLS connection
	clientTLSConn := tls.Client(clientConn, clientTLSConfig)
	defer clientTLSConn.Close()

	// Perform TLS handshake
	err = clientTLSConn.Handshake()
	require.NoError(t, err)

	// Write test request
	req, err := http.NewRequest(http.MethodGet, "https://"+upstreamServerName, nil)
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

func TestGroupHeaderInjection(t *testing.T) {
	proxyLogger, routerLogger, translatorLogger, echoLogger := setupTestLoggers()
	// Create test configuration
	config := &Config{
		CertFile:              "auto",
		KeyFile:               "auto",
		CAFile:                "",
		ServerName:            testServerSNI,
		InternalDomain:        testInternalDomain,
		ExternalDomain:        testExternalDomain,
		CertOptions: certstore.CertificateOptions{
			DNSNames:              []string{fmt.Sprintf("*.%s", testInternalDomain)},
		},
		CertStoreType:         "auto",
		CertStoreTTL:          24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		AllowUnknownCerts:     true,
		AutoMapCN:             true,
		ListenAddr:            "127.0.0.1:8445",
		EchoName:              testEchoSNI,
		EchoAddr:              "127.0.0.1:9445",
		ProxyLogger:          proxyLogger,
		RouterLogger:         routerLogger,
		TranslatorLogger:     translatorLogger,
		EchoLogger:          echoLogger,
	}

	// Initialize proxy
	p, err := New(config)
	require.NoError(t, err)

	// Add static route for echo server
	p.AddStaticRoute(testEchoSNI, config.EchoAddr)

	// Add group mapping - when CN is testClientSNI, assign TestGroup
	p.Translator().AddGroupMapping("cn", testClientSNI, []string{"TestGroup"})

	// Add group header injection (based on upstream SNI, i.e. app name)
	err = p.AddCommonHeader("groups", upstreamServerName, "X-Echo-Groups")
	require.NoError(t, err)

	// Start echo server and proxy server in goroutine
	go func() {
		err := p.ListenAndServe(config)
		if err != nil {
			t.Errorf("proxy server failed: %v", err)
		}
	}()

	// Wait for both servers to be ready
	require.NoError(t, waitForServer(t, config.ListenAddr))
	require.NoError(t, waitForServer(t, config.EchoAddr))

	// Create client connection
	clientConn, err := net.Dial("tcp", config.ListenAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Configure client TLS
	clientCert, err := p.certStore.GetCertificate(context.Background(), testClientSNI)
	require.NoError(t, err)

	clientTLSConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		RootCAs:            p.certStore.GetCertPool(),
		ServerName:         upstreamServerName,
	}

	// Create TLS connection
	clientTLSConn := tls.Client(clientConn, clientTLSConfig)
	defer clientTLSConn.Close()

	// Perform TLS handshake
	err = clientTLSConn.Handshake()
	require.NoError(t, err)

	// Write test request
	req, err := http.NewRequest(http.MethodGet, "https://"+upstreamServerName, nil)
	require.NoError(t, err)

	err = req.Write(clientTLSConn)
	require.NoError(t, err)

	// Read response with timeout
	clientTLSConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), nil)
	require.NoError(t, err)

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check that groups were properly injected
	assert.Equal(t, "TestGroup", resp.Header.Get("X-Echo-Groups"))
}

// waitForServer attempts to connect to the server address with retries
func waitForServer(t *testing.T, addr string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server failed to start within timeout")
}
