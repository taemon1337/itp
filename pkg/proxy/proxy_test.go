package proxy

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testInternalDomain = "internal.test"
	testExternalDomain = "external.test"
	testClientServerName      = "test-client"
	testServerServerName      = "test-server"
	testEchoServerName        = "test-upstream"
	testProxyServerName       = "test-proxy"
	testEchoServerNameInternal = "test-upstream.internal.test"
	testEchoServerNameExternal = "test-upstream.external.test"
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
			name:     "IPv4 address",
			addr:     "192.168.1.1:443",
			expected: "localhost", // any 172|192 address is considered localhost
		},
		{
			name:     "IPv6 address",
			addr:     "[2001:db8::1]:443",
			expected: "",
		},
		{
			name:     "Hostname",
			addr:     "example.com:443",
			expected: "example.com",
		},
		{
			name:     "Hostname with port",
			addr:     "test.example.com:8443",
			expected: "test.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyLogger, routerLogger, translatorLogger, echoLogger := setupTestLoggers()
			proxy := &Proxy{
				proxyLogger:      proxyLogger,
				routerLogger:     routerLogger,
				translatorLogger: translatorLogger,
				echoLogger:      echoLogger,
			}
			conn := &mockConn{addr: mockAddr{network: "tcp", address: tt.addr}}
			result := proxy.getDefaultSNI(conn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewProxy(t *testing.T) {
	// Create config with echo server
	config := NewProxyConfig(testProxyServerName, testExternalDomain, testInternalDomain)
	config.EchoName = testEchoServerName
	config.EchoAddr = "localhost:8080"
	// Enable both upstream and downstream header injection for testing
	config.InjectHeadersUpstream = true
	config.InjectHeadersDownstream = true
	config.ListenAddr = ":8443"
	config.EchoAddr = ":8453"
	config.AllowUnknownCerts = true

	// Configure server cert store with default certificate options
	config.CertStoreConfig.CommonName = testProxyServerName
	config.DefaultCertOptions = &certstore.CertificateOptions{
		CommonName: testProxyServerName,
		TTL:        24 * time.Hour, // Override store's DefaultTTL
		DNSNames: []string{
			"localhost",
			testProxyServerName,
			fmt.Sprintf("*.%s", testExternalDomain),
		},
	}

	// Configure echo cert store with default certificate options
	config.EchoDefaultCertOptions = &certstore.CertificateOptions{
		CommonName: testEchoServerName,
		TTL:        24 * time.Hour, // Override store's DefaultTTL
		DNSNames: []string{
			"localhost",
			testEchoServerNameInternal,
		},
	}

	p, err := NewProxy(config, logger.LevelDebug)
	require.NoError(t, err)

	assert.NotNil(t, p)
	assert.NotNil(t, p.router)
	assert.NotNil(t, p.translator)
	assert.NotNil(t, p.serverCertStore)
	assert.NotNil(t, p.internalCertStore)
	assert.Equal(t, config.AllowUnknownCerts, p.allowUnknownCerts)
	assert.True(t, p.AutoMapEnabled())

	// Get server certificate to validate options
	genServerStore, ok := p.serverCertStore.(*certstore.GeneratedStore)
	require.True(t, ok)
	serverCert, err := genServerStore.GetCertificateWithOptions(context.Background(), testProxyServerName, config.DefaultCertOptions)
	require.NoError(t, err)
	x509ServerCert, err := x509.ParseCertificate(serverCert.Certificate[0])
	require.NoError(t, err)

	// Validate server certificate
	assert.Equal(t, testProxyServerName, x509ServerCert.Subject.CommonName)
	assert.True(t, x509ServerCert.NotBefore.Before(time.Now()))
	assert.True(t, x509ServerCert.NotAfter.After(time.Now()))
	// Certificate should expire in ~24h (plus small buffer for test timing)
	assert.True(t, x509ServerCert.NotAfter.Before(time.Now().Add(26*time.Hour))) // 24h TTL + 2h buffer

	// Get echo certificate to validate options
	genEchoStore, ok := p.internalCertStore.(*certstore.GeneratedStore)
	require.True(t, ok)
	echoCert, err := genEchoStore.GetCertificateWithOptions(context.Background(), fmt.Sprintf("echo.%s", testInternalDomain), config.EchoDefaultCertOptions)
	require.NoError(t, err)
	x509EchoCert, err := x509.ParseCertificate(echoCert.Certificate[0])
	require.NoError(t, err)

	// Validate echo certificate
	assert.Equal(t, fmt.Sprintf("echo.%s", testInternalDomain), x509EchoCert.Subject.CommonName)
	assert.True(t, x509EchoCert.NotBefore.Before(time.Now()))
	assert.True(t, x509EchoCert.NotAfter.After(time.Now()))
	// Certificate should expire in ~24h (plus small buffer for test timing)
	assert.True(t, x509EchoCert.NotAfter.Before(time.Now().Add(26*time.Hour))) // 24h TTL + 2h buffer
}

func TestHandleConnection(t *testing.T) {
	config := NewProxyConfig(testProxyServerName, testExternalDomain, testInternalDomain)
	// Enable both upstream and downstream header injection for testing
	config.InjectHeadersUpstream = true
	config.InjectHeadersDownstream = true
	config.ListenAddr = "127.0.0.1:8443"
	config.EchoAddr = "127.0.0.1:8453"
	config.WithEchoServer(testEchoServerName)

	// Initialize proxy
	p, err := NewProxy(config, logger.LevelDebug)
	require.NoError(t, err)

	// Add static route for echo server
	p.AddStaticRoute(testEchoServerNameExternal, config.EchoAddr) // Use external name since that's what clients connect with

	// Add header template for client CN
	err = p.AddHeader(testEchoServerNameExternal, "X-Client-CN", "{{ .CommonName }}") // Use external name since that's what clients use
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

	// Get client certificate from internal store
	clientCert, err := p.serverCertStore.GetCertificate(context.Background(), testClientServerName)
	require.NoError(t, err)

	// Create HTTP client with TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*clientCert},
				RootCAs:     p.serverCertStore.GetCertPool(), // Trust server CA to verify proxy's cert
				ServerName:  testEchoServerNameExternal, // we use external domain heading into the proxy
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s", config.ListenAddr))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, testClientServerName, resp.Header.Get("X-Client-CN"))
}

func TestHeaderInjection(t *testing.T) {
	config := NewProxyConfig(testProxyServerName, testExternalDomain, testInternalDomain)
	// Enable both upstream and downstream header injection for testing
	config.InjectHeadersUpstream = true
	config.InjectHeadersDownstream = true
	config.ListenAddr = "127.0.0.1:8444"
	config.EchoAddr = "127.0.0.1:8454"
	config.WithEchoServer(testEchoServerName)

	// Initialize proxy
	p, err := NewProxy(config, logger.LevelDebug)
	require.NoError(t, err)

	// Add static route for echo server
	p.AddStaticRoute(testEchoServerNameExternal, config.EchoAddr) // Use external name since that's what clients connect with

	// Add identity mappings for testing
	p.translator.AddMapping("cn", testClientServerName, "mapped-user")
	p.translator.AddRoleMapping("cn", testClientServerName, []string{"developer"})
	p.translator.AddGroupMapping("cn", testClientServerName, []string{"dev-team"})

	// Add header templates with more test cases
	err = p.AddHeader(testEchoServerNameExternal, "X-Custom", "{{ .CommonName }}") // Use external name since that's what clients use
	require.NoError(t, err)

	err = p.AddHeader(testEchoServerNameExternal, "X-Groups", "{{ .Groups | comma }}") // Use external name since that's what clients use
	require.NoError(t, err)

	err = p.AddHeader(testEchoServerNameExternal, "X-Roles", "{{ .Roles | comma }}") // Use external name since that's what clients use
	require.NoError(t, err)

	err = p.AddCommonHeader("cn", testEchoServerNameExternal, "X-Common-CN") // Use external name since that's what clients use
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

	// Get client certificate from internal store
	clientCert, err := p.serverCertStore.GetCertificate(context.Background(), testClientServerName)
	require.NoError(t, err)

	// Create HTTP client with TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*clientCert},
				RootCAs:     p.serverCertStore.GetCertPool(), // Trust server CA to verify proxy's cert
				ServerName:  testEchoServerNameExternal, // we use external domain heading into the proxy
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s", config.ListenAddr))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "mapped-user", resp.Header.Get("X-Custom")) // CommonName is the mapped identity
	assert.Equal(t, "dev-team", resp.Header.Get("X-Groups"))
	assert.Equal(t, "developer", resp.Header.Get("X-Roles"))
	assert.Equal(t, "mapped-user", resp.Header.Get("X-Common-CN"))
}

func TestGroupHeaderInjection(t *testing.T) {
	config := NewProxyConfig(testProxyServerName, testExternalDomain, testInternalDomain)
	// Enable both upstream and downstream header injection for testing
	config.InjectHeadersUpstream = true
	config.InjectHeadersDownstream = true
	config.ListenAddr = "127.0.0.1:8445"
	config.EchoAddr = "127.0.0.1:8455"
	config.WithEchoServer(testEchoServerName)

	// Initialize proxy
	p, err := NewProxy(config, logger.LevelDebug)
	require.NoError(t, err)

	// Add static route for echo server
	p.AddStaticRoute(testEchoServerNameExternal, config.EchoAddr) // Use external name since that's what clients connect with

	// Add group mapping for test client
	p.translator.AddGroupMapping("cn", testClientServerName, []string{"TestGroup"})

	// Add header template for groups
	err = p.AddHeader(testEchoServerNameExternal, "X-Echo-Groups", "{{ range .Groups }}{{ . }}{{ end }}") // Use external name since that's what clients use
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

	// Get client certificate from server/external store (since in this test we are connecting to proxy which is then proxying to echo/internal)
	clientCert, err := p.serverCertStore.GetCertificate(context.Background(), testClientServerName)
	require.NoError(t, err)

	// Create HTTP client with TLS config
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{*clientCert},
				RootCAs:     p.serverCertStore.GetCertPool(), // Trust server CA to verify proxy's cert
				ServerName:  testEchoServerNameExternal, // we use external domain heading into the proxy
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s", config.ListenAddr))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)
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

func TestAddHeader(t *testing.T) {
	p := &Proxy{
		config: &Config{
			InjectHeadersUpstream:   true,
			InjectHeadersDownstream: false,
		},
		proxyLogger:      logger.New("proxy", logger.LevelInfo),
		routerLogger:     logger.New("router", logger.LevelInfo),
		translatorLogger: logger.New("translator", logger.LevelInfo),
		echoLogger:      logger.New("echo", logger.LevelInfo),
		headerInjector:   NewHeaderInjector(logger.New("header", logger.LevelInfo)),
	}

	// Test adding a header template
	err := p.AddHeader("test-upstream.external.test", "X-Test", "{{ .CommonName }}") // Use fully qualified external domain
	require.NoError(t, err)

	// Test adding an invalid template
	err = p.AddHeader("test-upstream.external.test", "X-Invalid", "{{ .Invalid }}") // Use fully qualified external domain
	require.Error(t, err)
}

// TestClientCertVerification tests the client certificate verification behavior
// with and without allowUnknownCerts enabled
func TestClientCertVerification(t *testing.T) {
	// Setup test loggers
	proxyLogger, _, _, _ := setupTestLoggers()

	// Create a separate CA for "unknown" certificates
	unknownCA, err := certstore.NewGeneratedStore(&certstore.StoreOptions{
		CommonName: "unknown-ca.test",
		KeyUsage:   x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DefaultTTL:  24 * time.Hour, // 24 hours for test certificates
	})
	require.NoError(t, err)

	// Generate an "unknown" client certificate signed by the unknown CA
	unknownClientCert, err := unknownCA.GetCertificateWithOptions(context.Background(), "unknown-client", &certstore.CertificateOptions{
		CommonName: "unknown-client",
		KeyUsage:   x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		TTL:        24 * time.Hour, // 24 hours for test certificates
	})
	require.NoError(t, err)

	// Create test cases
	tests := []struct {
		name               string
		allowUnknownCerts  bool
		clientCert         *tls.Certificate
		expectHandshakeErr bool
	}{
		{
			name:               "Known cert with verification",
			allowUnknownCerts:  false,
			clientCert:         nil, // Will use default test cert
			expectHandshakeErr: false,
		},
		{
			name:               "Unknown cert with verification",
			allowUnknownCerts:  false,
			clientCert:         unknownClientCert,
			expectHandshakeErr: true,
		},
		{
			name:               "Unknown cert without verification",
			allowUnknownCerts:  true,
			clientCert:         unknownClientCert,
			expectHandshakeErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create proxy config with proper cert stores
			config := &Config{
				ServerName:        testProxyServerName,
				ExternalDomain:    testExternalDomain,
				InternalDomain:    testInternalDomain,
				AllowUnknownCerts: tc.allowUnknownCerts,
				CertStoreConfig: &certstore.StoreOptions{
					CommonName: testProxyServerName,
					KeyUsage:   x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
					DefaultTTL:  24 * time.Hour, // 24 hours for test certificates
				},
				DefaultCertOptions: &certstore.CertificateOptions{
					CommonName: testProxyServerName,
					DNSNames: []string{"localhost", testProxyServerName},
					IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
					TTL:        24 * time.Hour, // 24 hours for test certificates
				},
			}

					// Create server CA for incoming client certs
			serverCA, err := certstore.NewGeneratedStore(&certstore.StoreOptions{
				CommonName: "server-ca.test",
				KeyUsage:   x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				DefaultTTL:  24 * time.Hour, // 24 hours for test certificates
			})
			require.NoError(t, err)

			// Create internal CA for upstream connections
			internalCA, err := certstore.NewGeneratedStore(&certstore.StoreOptions{
				CommonName: "internal-ca.test",
				KeyUsage:   x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				DefaultTTL:  24 * time.Hour, // 24 hours for test certificates
			})
			require.NoError(t, err)

			// Create proxy with proper cert stores
			proxy := &Proxy{
				config:           config,
				proxyLogger:      proxyLogger,
				serverCertStore:  serverCA,   // For verifying incoming client certs
				internalCertStore: internalCA, // For verifying upstream connections
			}

			// Get TLS config
			tlsConfig, err := proxy.createServerTLSConfig(config)
			require.NoError(t, err)

			// Create test server
			listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
			require.NoError(t, err)
			defer listener.Close()

			// Channel to coordinate server shutdown
			done := make(chan bool)

			// Start server in goroutine
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					close(done)
					return // Listener closed
				}
				defer conn.Close()

				// Complete TLS handshake
				tlsConn := conn.(*tls.Conn)
				err = tlsConn.Handshake()
				if err != nil {
					close(done)
					return
				}

				// Signal success
				close(done)
			}()

			// Create client config
			clientConfig := &tls.Config{
				RootCAs: serverCA.GetCertPool(), // Use server CA to verify server's certificate
			}

			// Use provided cert or default test cert
			if tc.clientCert != nil {
				clientConfig.Certificates = []tls.Certificate{*tc.clientCert}
			} else {
				// Get a client cert from the server's CA - this should be trusted
				clientCert, err := serverCA.GetCertificateWithOptions(context.Background(), testClientServerName, &certstore.CertificateOptions{
					CommonName:  testClientServerName,
					KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
				})
				require.NoError(t, err)
				clientConfig.Certificates = []tls.Certificate{*clientCert}
			}

			// Try to connect
			conn, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
			if tc.expectHandshakeErr {
				assert.Error(t, err, "Expected handshake to fail")
			} else {
				assert.NoError(t, err, "Expected handshake to succeed")
				if err == nil {
					// Complete handshake
					err = conn.Handshake()
					assert.NoError(t, err, "Expected handshake to succeed")
					conn.Close()
				}
			}

			// Wait for server to complete
			<-done
		})
	}
}

func TestProxyWithPreserveTLS(t *testing.T) {
	// Initialize test configuration
	config := NewProxyConfig(testProxyServerName, testExternalDomain, testInternalDomain)
	config.AllowUnknownCerts = true
	config.WithEchoServer(testEchoServerName)

	// Create proxy instance
	p, err := NewProxy(config, logger.LevelDebug)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Add route with PreserveTLS flag
	p.AddStaticRoute("external.example.com", "tls://api.external.com:8443")

	// Get client certificate
	clientCert, err := p.serverCertStore.GetCertificate(context.Background(), testClientServerName)
	if err != nil {
		t.Fatalf("Failed to get client certificate: %v", err)
	}

	// Create a test server that verifies the client's SNI
	var receivedSNI string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			receivedSNI = hello.ServerName
			return &tls.Config{
				Certificates: []tls.Certificate{*clientCert},
			}, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	// Update the route to point to our test server
	p.AddStaticRoute("external.example.com", "tls://"+strings.TrimPrefix(server.URL, "https://"))

	// Create test client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      p.serverCertStore.GetCertPool(),
				Certificates: []tls.Certificate{*clientCert},
				ServerName:   "external.example.com",
				InsecureSkipVerify: true, // Skip verification since we're using a self-signed cert
			},
		},
	}

	// Start proxy server
	go func() {
		if err := p.ListenAndServe(config); err != nil {
			t.Errorf("Proxy server error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond) // Wait for server to start

	// Send request to our test server through the proxy
	resp, err := client.Get("https://external.example.com/test")
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Verify response and SNI
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// The proxy should have used api.external.com as the SNI when connecting to our test server
	assert.Equal(t, "api.external.com", receivedSNI, "Wrong SNI used for upstream connection")
}

func TestTemplates(t *testing.T) {
	// Create proxy
	config := NewProxyConfig(testProxyServerName, testExternalDomain, testInternalDomain)
	p, err := NewProxy(config, logger.LevelInfo)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	// Test adding template string
	err = p.AddTemplate("user-info", "User:{{.CommonName}};Roles:{{join .Roles \"; \"}}")
	if err != nil {
		t.Errorf("Failed to add template: %v", err)
	}

	// Test using template in header
	err = p.AddHeader("echo.example.com", "X-User-Info", "{{template \"user-info\"}}")
	if err != nil {
		t.Errorf("Failed to add header with template: %v", err)
	}

	// Test adding template from file
	tmpfile, err := os.CreateTemp("", "template-*.tmpl")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write template content
	content := "Groups:{{join .Groups \"; \"}}"
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write template: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close template file: %v", err)
	}

	// Add template from file
	err = p.AddTemplateFile("groups-info", tmpfile.Name())
	if err != nil {
		t.Errorf("Failed to add template from file: %v", err)
	}

	// Test using file template in header
	err = p.AddHeader("echo.example.com", "X-Groups-Info", "{{template \"groups-info\"}}")
	if err != nil {
		t.Errorf("Failed to add header with file template: %v", err)
	}

	// Test invalid template
	err = p.AddTemplate("invalid", "{{.Invalid}}")
	if err == nil {
		t.Error("Expected error for invalid template")
	}

	// Test non-existent template file
	err = p.AddTemplateFile("nonexistent", "nonexistent.tmpl")
	if err == nil {
		t.Error("Expected error for non-existent template file")
	}
}

func TestAddCommonHeader(t *testing.T) {
	p := &Proxy{
		config: &Config{
			InjectHeadersUpstream:   true,
			InjectHeadersDownstream: false,
		},
		proxyLogger:      logger.New("proxy", logger.LevelInfo),
		routerLogger:     logger.New("router", logger.LevelInfo),
		translatorLogger: logger.New("translator", logger.LevelInfo),
		echoLogger:      logger.New("echo", logger.LevelInfo),
		headerInjector:   NewHeaderInjector(logger.New("header", logger.LevelInfo)),
		translator:       identity.NewTranslator(logger.New("translator", logger.LevelInfo), true),
	}

	// Test adding a common header
	err := p.AddCommonHeader("cn", "test-upstream.external.test", "X-Common") // Use fully qualified external domain
	require.NoError(t, err)

	// Test adding a header with invalid field
	err = p.AddCommonHeader("invalid", "test-upstream.external.test", "X-Invalid") // Use fully qualified external domain
	require.Error(t, err)
}
