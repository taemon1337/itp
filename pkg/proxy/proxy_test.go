package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"bufio"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/echo"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"crypto/x509"
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

func TestHandleConnection(t *testing.T) {
	tests := []struct {
		name              string
		serverName        string
		routeViaDNS       bool
		staticRoutes      map[string]string
		echoName          string
		echoAddr          string
		clientCertCN      string
		clientCertOrg     []string
		allowUnknownCerts bool
		autoMap           bool
		expectedStatus    int
		expectedResponse  string
	}{
		{
			name:           "no route found",
			serverName:     "unknown.example.com",
			routeViaDNS:    false,
			expectedStatus: http.StatusNotFound,
			expectedResponse: "No route found for unknown.example.com",
		},
		{
			name:           "no client certificate",
			serverName:     "example.com",
			staticRoutes: map[string]string{
				"example.com": "10.0.0.1:443",
			},
			allowUnknownCerts: false,
			expectedStatus:    http.StatusUnauthorized,
			expectedResponse:  "No verified client certificate chain",
		},
		{
			name:           "unverified client certificate when verification required",
			serverName:     "example.com",
			staticRoutes: map[string]string{
				"example.com": "10.0.0.1:443",
			},
			clientCertCN:      "test-client",
			allowUnknownCerts: false,
			expectedStatus:    http.StatusUnauthorized,
			expectedResponse:  "No verified client certificate chain",
		},
		{
			name:           "no identity mappings found",
			serverName:     "example.com",
			staticRoutes: map[string]string{
				"example.com": "10.0.0.1:443",
			},
			clientCertCN:      "test-client",
			clientCertOrg:     []string{"test-org"},
			allowUnknownCerts: true,
			autoMap:           false,
			expectedStatus:    http.StatusForbidden,
			expectedResponse:  "Access denied: no identity mappings found",
		},
		{
			name:           "route via DNS when disabled",
			serverName:     "localhost",
			routeViaDNS:    false,
			expectedStatus: http.StatusNotFound,
			expectedResponse: "No route found for localhost",
		},
		{
			name:           "route via DNS with invalid hostname",
			serverName:     "invalid..hostname",
			routeViaDNS:    true,
			expectedStatus: http.StatusInternalServerError,
			expectedResponse: "DNS lookup failed",
		},
		{
			name:           "route to echo server",
			serverName:     "echo.local",
			staticRoutes: map[string]string{
				"echo.local": "echo.test",
			},
			echoName:          "echo.test",
			echoAddr:          "localhost:8444",
			clientCertCN:      "test-client",
			allowUnknownCerts: true,
			autoMap:           true,
			expectedStatus:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create router
			r := router.NewRouter(tt.routeViaDNS)
			if tt.echoName != "" {
				r.SetEchoUpstream(tt.echoName, tt.echoAddr)
			}
			for src, dest := range tt.staticRoutes {
				r.AddStaticRoute(src, dest)
			}

			// Create translator
			translator := identity.NewTranslator(tt.autoMap)

			// Create generated cert store
			var certStore certstore.Store
			var err error
			certStore, err = certstore.NewGeneratedStore(certstore.GeneratedOptions{
				CommonName:     "test-ca",
				Expiry:        24 * time.Hour,
				DefaultTTL:    time.Hour,
				CacheDuration: time.Hour,
			})
			require.NoError(t, err)

			// Create proxy
			p := New(r, translator, certStore, tt.allowUnknownCerts)

			// Start echo server if needed
			var echoListener net.Listener
			if tt.echoName != "" {
				var err error
				echoCert, err := certStore.GetCertificate(context.Background(), "echo-server")
				require.NoError(t, err)

				// Get root CA from cert store
				var rootCAs *x509.CertPool
				genStore := certStore.(*certstore.GeneratedStore)
				rootCAs = x509.NewCertPool()
				rootCAs.AddCert(genStore.GetCACertificate())

				// Create TLS config for echo server
				echoConfig := &tls.Config{
					Certificates: []tls.Certificate{*echoCert},
					ClientAuth:   tls.RequestClientCert,
					RootCAs:     rootCAs,
					// Allow any client cert since we're just testing
					ClientCAs:              rootCAs,
					VerifyPeerCertificate:  nil,
					InsecureSkipVerify:     true,
					ServerName:             "echo-server",
				}

				// Start echo server with TLS
				echoListener, err = tls.Listen("tcp", "127.0.0.1:0", echoConfig)
				require.NoError(t, err)

				// Start echo server
				echoServer := echo.New(echoCert, tt.echoName)
				echoAddr := echoListener.Addr().String()
				echoListener.Close() // Close the listener before starting the echo server
				err = echoServer.Start(echoAddr)
				require.NoError(t, err)
				defer echoServer.Stop()

				// Update router with actual echo server address
				r.SetEchoUpstream(tt.echoName, echoAddr)
			}

			// Create a listener for proxy
			proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer proxyListener.Close()

			// Start proxy in a goroutine
			go func() {
				conn, err := proxyListener.Accept()
				if err != nil {
					t.Errorf("Failed to accept connection: %v", err)
					return
				}

				// Get server certificate
				serverCert, err := certStore.GetCertificate(context.Background(), "test-server")
				if err != nil {
					t.Errorf("Failed to get server certificate: %v", err)
					return
				}

				// Create TLS config for server
				serverConfig := &tls.Config{
					Certificates: []tls.Certificate{*serverCert},
					ClientAuth:   tls.RequestClientCert,
				}

				// Wrap connection in TLS
				tlsConn := tls.Server(conn, serverConfig)
				p.HandleConnection(tlsConn)
			}()

			// Get root CA from cert store
			rootCAs := x509.NewCertPool()
			genStore := certStore.(*certstore.GeneratedStore)
			rootCAs.AddCert(genStore.GetCACertificate())

			// Create TLS config for client
			clientConfig := &tls.Config{
				ServerName:         tt.serverName,
				RootCAs:           rootCAs,
				InsecureSkipVerify: true,
			}

			// Add client certificate if specified
			if tt.clientCertCN != "" {
				cert, err := certStore.GetCertificate(context.Background(), tt.clientCertCN)
				require.NoError(t, err)
				clientConfig.Certificates = []tls.Certificate{*cert}
			}

			// Connect to proxy
			proxyConn, err := tls.Dial("tcp", proxyListener.Addr().String(), clientConfig)
			require.NoError(t, err)
			defer proxyConn.Close()

			// Write request
			req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", tt.serverName)
			_, err = proxyConn.Write([]byte(req))
			require.NoError(t, err)

			// Read response with timeout
			proxyConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(proxyConn), nil)
			require.NoError(t, err)

			// Check status code
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			// Check response body if expected
			if tt.expectedResponse != "" {
				body, err := io.ReadAll(resp.Body)
				assert.NoError(t, err)
				assert.Contains(t, string(body), tt.expectedResponse)
			}
		})
	}
}

func TestNew(t *testing.T) {
	r := &router.Router{}
	tr := &identity.Translator{}
	store, err := certstore.NewGeneratedStore(certstore.GeneratedOptions{
		CommonName:     "Test CA",
		Expiry:        24 * time.Hour,
		DefaultTTL:    1 * time.Hour,
		CacheDuration: 5 * time.Minute,
	})
	assert.NoError(t, err)
	allowUnknown := true

	p := New(r, tr, store, allowUnknown)

	assert.NotNil(t, p)
	assert.Equal(t, r, p.router)
	assert.Equal(t, tr, p.translator)
	assert.Equal(t, store, p.certStore)
	assert.Equal(t, allowUnknown, p.allowUnknownCerts)
}
