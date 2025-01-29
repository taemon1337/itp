package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/itp/pkg/echo"
	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/logger"
	"github.com/itp/pkg/router"
	"bufio"
)

// Proxy handles the connection proxying and identity translation
type Proxy struct {
	router            *router.Router
	translator        *identity.Translator
	certStore         certstore.Store
	config            Config
	allowUnknownCerts bool
	headerInjector    *HeaderInjector
	logger           *logger.Logger
}

// Config represents TLS configuration options for the proxy
type Config struct {
	// Server TLS config
	CertFile           string
	KeyFile            string
	CAFile            string
	AllowUnknownCerts bool
	ListenAddr        string

	// Echo server config
	EchoName         string // Name for the echo upstream (empty to disable)
	EchoAddr         string // Address for echo upstream server
	RouteViaDNS      bool  // Allow routing to unspecified destinations via DNS
	AutoMapCN        bool  // Automatically map client CN to upstream CN

	// Certificate store config
	CertStoreType    string // Type of certificate store (k8s or auto)
	CertStoreTTL     time.Duration
	CertStoreCacheDuration time.Duration
	CertStoreNamespace string // Only used for k8s store

	// Logger config
	ProxyLogger      *logger.Logger
	RouterLogger     *logger.Logger
	TranslatorLogger *logger.Logger
	EchoLogger      *logger.Logger
}

// New creates a new proxy instance with the given configuration
func New(config Config) (*Proxy, error) {
	// Initialize certificate store
	store, err := createCertStore(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate store: %v", err)
	}

	// Initialize router with logger
	router := router.NewRouter(config.RouterLogger, config.RouteViaDNS)

	// Initialize translator with logger
	translator := identity.NewTranslator(config.TranslatorLogger, config.AutoMapCN)

	return &Proxy{
		router:            router,
		translator:        translator,
		certStore:         store,
		config:            config,
		allowUnknownCerts: config.AllowUnknownCerts,
		headerInjector:    NewHeaderInjector(),
		logger:           config.ProxyLogger,
	}, nil
}

// AutoMapEnabled returns true if auto mapping is enabled
func (p *Proxy) AutoMapEnabled() bool {
	return p.config.AutoMapCN
}

// createCertStore creates a certificate store based on the configuration
func createCertStore(config Config) (certstore.Store, error) {
	switch config.CertStoreType {
	case "k8s":
		return certstore.NewK8sStore(certstore.K8sOptions{
			Options: certstore.Options{
				CacheDuration: config.CertStoreCacheDuration,
				DefaultTTL:    config.CertStoreTTL,
			},
			Namespace: config.CertStoreNamespace,
			Client:    nil, // TODO: Add k8s client initialization
		}), nil
	case "auto":
		return certstore.NewGeneratedStore(certstore.StoreOptions{
			CommonName:     "itp",
			TTL:           config.CertStoreTTL,
			CacheDuration: config.CertStoreCacheDuration,
			KeyUsage:      x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		})
	default:
		return nil, fmt.Errorf("unknown certificate store type: %s", config.CertStoreType)
	}
}

// AddHeader adds a header template for an upstream
func (p *Proxy) AddHeader(upstream, headerName, template string) error {
	return p.headerInjector.AddHeader(upstream, headerName, template)
}

// AddCommonHeader adds a common header (groups, roles, etc) for an upstream
func (p *Proxy) AddCommonHeader(headerType, upstream, headerName string) error {
	return p.headerInjector.AddCommonHeader(headerType, upstream, headerName)
}

// getDefaultSNI returns a default SNI based on the connection details
func (p *Proxy) getDefaultSNI(conn net.Conn) string {
	// Get the host part from the local address
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return ""
	}

	// If it's localhost or 127.0.0.1, use "localhost"
	if host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" || host == "::" {
		return "localhost"
	}

	// For other IPs, use the IP itself
	return host
}

// sendErrorResponse sends an HTTP error response to the client
func (p *Proxy) sendErrorResponse(conn net.Conn, statusCode int, message string) {
	resp := &http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader(message)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Connection", "close")
	resp.ContentLength = int64(len(message))
	
	if err := resp.Write(conn); err != nil {
		p.config.ProxyLogger.Error("Failed to write error response: %v", err)
	}
}

// handleErrorConnection handles a connection that has encountered an error before proxying started
func (p *Proxy) handleErrorConnection(conn net.Conn, statusCode int, message string) {
	p.config.ProxyLogger.Error("Connection error from %s: %s", conn.RemoteAddr(), message)
	resp := &http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader(message)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("Connection", "close")
	resp.ContentLength = int64(len(message))
	
	if err := resp.Write(conn); err != nil {
		p.config.ProxyLogger.Error("Failed to write error response: %v", err)
	}
}

// setupTLSConnection performs the initial TLS handshake and identity translation
func (p *Proxy) setupTLSConnection(conn net.Conn) (*tls.Conn, []*identity.Identity, string, error) {
	// Step 1: Validate TLS connection and perform handshake
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, nil, "", fmt.Errorf("connection must be TLS")
	}

	// Create a custom config that will capture the SNI
	var sni string
	_ = &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = info.ServerName
			return nil, nil
		},
	}
	tlsConn.HandshakeContext(context.Background())

	// Now attempt the real handshake
	if err := tlsConn.Handshake(); err != nil {
		msg := "TLS handshake failed"
		if sni != "" {
			msg = fmt.Sprintf("%s (SNI: %s)", msg, sni)
		}
		return nil, nil, "", fmt.Errorf(msg)
	}

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		msg := fmt.Sprintf("TLS handshake not completed (SNI: %s)", sni)
		return nil, nil, "", fmt.Errorf(msg)
	}

	// If no SNI was provided, use a default based on the connection
	if state.ServerName == "" {
		state.ServerName = p.getDefaultSNI(conn)
		p.config.ProxyLogger.Debug("No SNI provided, using default: %s", state.ServerName)
	}

	// Step 2: Verify client certificate
	var clientCert *x509.Certificate
	if len(state.PeerCertificates) > 0 {
		clientCert = state.PeerCertificates[0]
		p.config.ProxyLogger.Debug("Using verified client certificate from %s, subject: %s",
			conn.RemoteAddr(), clientCert.Subject)
	}

	// Step 3: Translate identity
	identities, err := p.translator.TranslateIdentity(clientCert)
	if err != nil {
		var msg string
		if translationErr, ok := err.(*identity.TranslationError); ok {
			switch translationErr.Code {
			case identity.ErrNoMappings:
				msg = fmt.Sprintf("Access denied: %s", translationErr.Message)
			case identity.ErrUnrecognizedClient:
				msg = fmt.Sprintf("Invalid certificate: %s", translationErr.Message)
			default:
				msg = fmt.Sprintf("Identity translation failed: %s", translationErr.Message)
			}
		} else {
			msg = fmt.Sprintf("Identity translation failed: %v", err)
		}
		return nil, nil, "", fmt.Errorf(msg)
	}

	return tlsConn, identities, state.ServerName, nil
}

// HandleConnection manages a proxied connection with identity translation
func (p *Proxy) HandleConnection(conn net.Conn) {
	defer conn.Close()

	// Setup TLS connection and translate identity
	tlsConn, identities, serverName, err := p.setupTLSConnection(conn)
	if err != nil {
		p.handleErrorConnection(conn, http.StatusBadRequest, err.Error())
		return
	}

	// Resolve destination
	destination, err := p.router.ResolveDestination(serverName)
	if err != nil {
		if strings.Contains(err.Error(), "no route found") {
			p.handleErrorConnection(conn, http.StatusNotFound, fmt.Sprintf("No route found for %s", serverName))
		} else {
			p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to resolve destination: %v", err))
		}
		return
	}

	// Check if this is an HTTP connection that needs header injection
	if len(p.headerInjector.GetHeaders(serverName, identities)) > 0 {
		p.handleHTTPConnection(conn, destination, serverName, identities)
		return
	}

	// Handle as TCP connection
	p.handleTCPConnection(conn, tlsConn, destination, identities)
}

// handleTCPConnection handles direct TCP proxying with TLS termination
func (p *Proxy) handleTCPConnection(conn net.Conn, tlsConn *tls.Conn, destination string, identities []*identity.Identity) {
	// Get certificate for upstream connection
	var upstreamCert *tls.Certificate
	var err error = nil
	if len(identities) == 1 && identities[0].CommonName == tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName {
		// If we're using the auto-mapped identity, get cert by CN
		cn := identities[0].CommonName
		upstreamCert, err = p.certStore.GetCertificate(context.Background(), cn)
		if err != nil {
			p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to get certificate for CN %s: %v", cn, err))
			return
		}
		p.config.ProxyLogger.Debug("Using auto-mapped certificate with CN: %s", cn)
	} else {
		upstreamCert, err = p.certStore.GetCertificate(context.Background(), destination)
		if err != nil {
			p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to get certificate for %s: %v", destination, err))
			return
		}
	}

	// Extract host from destination for TLS verification
	host := destination
	if h, _, err := net.SplitHostPort(destination); err == nil {
		host = h
	}

	// Create TLS config for upstream connection using cert store
	upstreamConfig := p.certStore.GetTLSClientConfig(upstreamCert, certstore.TLSClientOptions{
		ServerName: host,
	})

	// If connecting to echo server, use its name for TLS verification
	if echoName, echoAddr := p.router.GetEchoUpstream(); echoName != "" && destination == echoAddr {
		upstreamConfig.ServerName = echoName
	}

	// Connect to upstream
	upstreamConn, err := tls.Dial("tcp", destination, upstreamConfig)
	if err != nil {
		p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to connect to upstream: %v", err))
		return
	}
	defer upstreamConn.Close()

	// Create error channels for both directions
	errChan := make(chan error, 2)

	// Copy data bidirectionally
	go func() {
		_, err := io.Copy(upstreamConn, tlsConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(tlsConn, upstreamConn)
		errChan <- err
	}()

	// Wait for either direction to finish or error
	err = <-errChan
	if err != nil && err != io.EOF {
		p.config.ProxyLogger.Error("Error during TCP proxy: %v", err)
	}
}

// handleHTTPConnection handles HTTP-specific proxying, including header injection
func (p *Proxy) handleHTTPConnection(conn net.Conn, destination string, serverName string, identities []*identity.Identity) {
	p.config.ProxyLogger.Debug("Starting HTTP connection handling for destination: %s, server: %s", destination, serverName)

	// Get certificate for upstream connection
	upstreamCert, err := p.certStore.GetCertificate(context.Background(), destination)
	if err != nil {
		p.config.ProxyLogger.Error("Failed to get certificate: %v", err)
		p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to get certificate for %s: %v", destination, err))
		return
	}
	p.config.ProxyLogger.Debug("Got certificate for %s", destination)

	// Extract host from destination for TLS verification
	host := destination
	if h, _, err := net.SplitHostPort(destination); err == nil {
		host = h
	}
	p.config.ProxyLogger.Debug("Using host %s for TLS verification", host)

	// Create TLS config for upstream connection
	upstreamConfig := p.certStore.GetTLSClientConfig(upstreamCert, certstore.TLSClientOptions{
		ServerName: host,
	})

	// If connecting to echo server, use its name for TLS verification
	if echoName, echoAddr := p.router.GetEchoUpstream(); echoName != "" && destination == echoAddr {
		upstreamConfig.ServerName = echoName
		p.config.ProxyLogger.Debug("Using echo server name %s for TLS verification", echoName)
	}

	// Create buffered reader for the connection
	reader := bufio.NewReader(conn)

	// Read the HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.config.ProxyLogger.Error("Failed to read request: %v", err)
		return
	}

	p.config.ProxyLogger.Debug("Received request: %s %s", req.Method, req.URL.String())

	// Update request URL with destination
	req.URL.Scheme = "https"
	req.URL.Host = destination
	req.Host = destination

	// Add headers from injector for the server name
	headers := p.headerInjector.GetHeaders(serverName, identities)
	p.config.ProxyLogger.Debug("Got %d headers to inject for server %q", len(headers), serverName)
	for k, v := range headers {
		p.config.ProxyLogger.Debug("Injecting header %q = %q", k, v)
		req.Header.Set(k, v)
	}

	// Log final request headers
	p.config.ProxyLogger.Debug("Final request headers:")
	for k, v := range req.Header {
		p.config.ProxyLogger.Debug("  %s: %v", k, v)
	}

	// Create transport for upstream connection
	transport := &http.Transport{
		TLSClientConfig: upstreamConfig,
		DisableKeepAlives: true,
	}

	// Send the request to the upstream server
	resp, err := transport.RoundTrip(req)
	if err != nil {
		p.config.ProxyLogger.Error("Failed to send request: %v", err)
		p.handleErrorConnection(conn, http.StatusBadGateway, fmt.Sprintf("Failed to send request: %v", err))
		return
	}
	defer resp.Body.Close()

	p.config.ProxyLogger.Debug("Got response: %d %s", resp.StatusCode, resp.Status)
	p.config.ProxyLogger.Debug("Response headers:")
	for k, v := range resp.Header {
		p.config.ProxyLogger.Debug("  %s: %v", k, v)
	}

	// Write the response back to the client
	resp.Header.Set("Connection", "close")
	if err := resp.Write(conn); err != nil {
		p.config.ProxyLogger.Error("Failed to write response: %v", err)
		return
	}

	p.config.ProxyLogger.Debug("Successfully sent response")
}

// ListenAndServe starts the TLS proxy server
func (p *Proxy) ListenAndServe(config Config) error {
	// Start echo server if enabled
	if config.EchoName != "" {
		if err := p.setupEchoServer(config); err != nil {
			return fmt.Errorf("failed to setup echo server: %v", err)
		}
	}

	// Create TLS config
	tlsConfig, err := p.createTLSConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %v", err)
	}

	// Start listener
	ln, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener: %v", err)
	}
	defer ln.Close()

	tlsListener := tls.NewListener(ln, tlsConfig)
	defer tlsListener.Close()

	p.config.ProxyLogger.Info("listening on %s", config.ListenAddr)

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			p.config.ProxyLogger.Error("Failed to accept connection: %v", err)
			continue
		}
		go p.HandleConnection(conn)
	}
}

// setupEchoServer configures and starts the echo server
func (p *Proxy) setupEchoServer(config Config) error {
	// Get certificate from store using the provided echo name
	echoServerCert, err := p.certStore.GetCertificate(context.Background(), config.EchoName)
	if err != nil {
		return fmt.Errorf("failed to get echo server certificate: %v", err)
	}

	echoServer := echo.New(echoServerCert, p.certStore.GetCertPool(), config.EchoName)
	if err := echoServer.Start(config.EchoAddr); err != nil {
		return fmt.Errorf("failed to start echo server: %v", err)
	}

	// Configure router to use echo server
	p.router.SetEchoUpstream(config.EchoName, config.EchoAddr)
	p.config.ProxyLogger.Info("Echo upstream enabled as '%s' on %s", config.EchoName, config.EchoAddr)

	return nil
}

// createTLSConfig creates a TLS configuration based on the provided config
func (p *Proxy) createTLSConfig(config Config) (*tls.Config, error) {
	var serverCert *tls.Certificate

	if config.CertFile == "auto" {
		// Use auto-generated certificates for the server
		genStore, ok := p.certStore.(*certstore.GeneratedStore)
		if !ok {
			return nil, fmt.Errorf("auto server certificates require auto cert-store type")
		}

		// Load or create CA certificate
		var caCert *x509.Certificate
		if config.CAFile != "" {
			caBytes, err := os.ReadFile(config.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA file: %v", err)
			}
			block, _ := pem.Decode(caBytes)
			if block == nil {
				return nil, fmt.Errorf("failed to decode CA PEM")
			}
			caCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
			}
		} else {
			caCert = genStore.GetCACertificate()
		}

		// Save CA certificate if requested
		if config.CAFile != "" {
			if _, err := os.Stat(config.CAFile); os.IsNotExist(err) {
				caBytes := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: caCert.Raw,
				})
				if err := os.WriteFile(config.CAFile, caBytes, 0644); err != nil {
					p.config.ProxyLogger.Warn("Failed to save CA certificate to %s: %v", config.CAFile, err)
				}
			}
		}

		// Generate server certificate
		cert, err := genStore.GetCertificate(context.Background(), "server")
		if err != nil {
			return nil, fmt.Errorf("failed to generate server certificate: %v", err)
		}
		serverCert = cert
	} else {
		// Use file-based certificates
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server certificate: %v", err)
		}
		serverCert = &cert
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.RequestClientCert,
	}

	if !config.AllowUnknownCerts {
		// Only verify client certs if we're not allowing unknown clients
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		if config.CAFile != "" {
			// Load CA cert if provided
			caCert, err := os.ReadFile(config.CAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read CA cert: %v", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA cert")
			}
			tlsConfig.ClientCAs = caCertPool
		}
	}

	return tlsConfig, nil
}

// Translator returns the identity translator instance
func (p *Proxy) Translator() *identity.Translator {
	return p.translator
}

// AddStaticRoute adds a static route to the router
func (p *Proxy) AddStaticRoute(src, dest string) {
	p.router.AddStaticRoute(src, dest)
}

// AddRoutes adds static routes from a comma-separated string
func (p *Proxy) AddRoutes(routes string) {
	for _, route := range strings.Split(routes, ",") {
		parts := strings.Split(route, "=")
		if len(parts) != 2 {
			p.config.ProxyLogger.Error("Invalid route format: %s", route)
			continue
		}
		p.AddStaticRoute(parts[0], parts[1])
	}
}
