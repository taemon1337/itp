package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"bufio"
	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/echo"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/logger"
	"github.com/itp/pkg/router"
)

// Config contains proxy configuration
type Config struct {
	// Server configuration
	ListenAddr string
	ServerName string

	// Domain configuration
	InternalDomain string
	ExternalDomain string

	// Certificate configuration
	CertFile string
	KeyFile  string
	CAFile   string

	// Certificate store configuration
	CertStoreConfig *certstore.StoreOptions
	InternalStoreConfig *certstore.StoreOptions
	EchoStoreConfig *certstore.StoreOptions
	
	// Default certificate options
	DefaultCertOptions *certstore.CertificateOptions
	EchoDefaultCertOptions *certstore.CertificateOptions

	// Echo server configuration
	EchoName string
	EchoAddr string

	// Security configuration
	AllowUnknownCerts bool
	RouteViaDNS       bool
	AutoMapCN         bool

	// Header injection configuration
	InjectHeadersUpstream   bool
	InjectHeadersDownstream bool
}

// Proxy represents a TLS proxy instance
type Proxy struct {
	config            *Config
	allowUnknownCerts bool

	// Certificate stores
	serverCertStore   certstore.Store
	internalCertStore certstore.Store

	// Components
	router         *router.Router
	translator     *identity.Translator
	headerInjector *HeaderInjector

	// Loggers
	proxyLogger     *logger.Logger
	routerLogger    *logger.Logger
	translatorLogger *logger.Logger
	echoLogger      *logger.Logger
}

// NewConfig creates a new proxy configuration with the given parameters.
// Required parameters:
// - serverName: name of the proxy server (e.g. "proxy.example.com")
// - externalDomain: domain for external connections (e.g. "external.com")
// - internalDomain: domain for internal connections (e.g. "internal.local")
// Optional parameters can be set after creation:
// - CertFile, KeyFile, CAFile: for custom certificates
// - EchoName, EchoAddr: for echo server configuration
// - AllowUnknownCerts: for relaxed client cert verification
// - RouteViaDNS: for DNS-based routing
func NewProxyConfig(serverName, externalDomain, internalDomain string) *Config {
	if serverName == "" {
		serverName = "proxy.test"
	}
	if externalDomain == "" {
		externalDomain = "external.com"
	}
	if internalDomain == "" {
		internalDomain = "internal.local"
	}

	// Create base config
	config := &Config{
		ListenAddr:     ":8443",
		ServerName:     serverName,
		InternalDomain: internalDomain,
		ExternalDomain: externalDomain,
		EchoAddr:      ":8444",
		AutoMapCN:     true, // Enable by default for convenience
		
		// Enable header injection upstream by default
		InjectHeadersUpstream:   true,
		InjectHeadersDownstream: false,

		AllowUnknownCerts: false,
		RouteViaDNS:       false,
	}

	// Configure server certificate store with 30 days TTL
	config.CertStoreConfig = &certstore.StoreOptions{
		CommonName: serverName,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CacheDuration: time.Hour,
		DefaultTTL: 30 * 24 * time.Hour,
	}

	// Configure internal certificate store with 30 days TTL
	config.InternalStoreConfig = &certstore.StoreOptions{
		CommonName: "internal." + internalDomain,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CacheDuration: time.Hour,
		DefaultTTL: 30 * 24 * time.Hour,
	}

	return config
}

// WithEchoServer configures the echo server settings
func (c *Config) WithEchoServer(name string) *Config {
	c.EchoName = name
	if !strings.HasSuffix(name, c.InternalDomain) {
		c.EchoName = fmt.Sprintf("%s.%s", name, c.InternalDomain)
	}
	
	c.EchoStoreConfig = &certstore.StoreOptions{
		CommonName: c.EchoName,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		CacheDuration: time.Hour,
		DefaultTTL: 30 * 24 * time.Hour,
	}

	return c
}

// WithCertificates configures custom certificates
func (c *Config) WithCertificates(certFile, keyFile, caFile string) *Config {
	c.CertFile = certFile
	c.KeyFile = keyFile
	c.CAFile = caFile
	return c
}

// New creates a new proxy instance with the given configuration
func NewProxy(config *Config) (*Proxy, error) {
	var err error
	p := &Proxy{
		config:            config,
		allowUnknownCerts: config.AllowUnknownCerts,
		proxyLogger:      logger.New("proxy", logger.LevelInfo),
		routerLogger:     logger.New("router", logger.LevelInfo),
		translatorLogger: logger.New("translator", logger.LevelInfo),
		echoLogger:      logger.New("echo", logger.LevelInfo),
	}

	// Create cert stores
	p.serverCertStore, err = certstore.NewGeneratedStore(config.CertStoreConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create server cert store: %v", err)
	}
	// Internal cert store for internal domain (clients and upstreams)
	p.internalCertStore, err = certstore.NewGeneratedStore(config.InternalStoreConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal cert store: %v", err)
	}
	// Create router
	p.router = router.NewRouter(p.routerLogger, config.RouteViaDNS)

	// Create translator
	p.translator = identity.NewTranslator(p.translatorLogger, config.AutoMapCN)

	// Create header injector
	p.headerInjector = NewHeaderInjector()

	return p, nil
}

// AutoMapEnabled returns true if auto mapping is enabled
func (p *Proxy) AutoMapEnabled() bool {
	return p.config.AutoMapCN
}

// createCertStore creates a certificate store based on the configuration
func createCertStore(config *Config) (certstore.Store, error) {
	store, err := certstore.NewGeneratedStore(config.CertStoreConfig)
	if err != nil {
		return nil, err
	}

	// If default cert options are provided, set them up
	if config.DefaultCertOptions != nil {
		// Generate a certificate with the default options to ensure they work
		_, err := store.GetCertificateWithOptions(context.Background(), config.CertStoreConfig.CommonName, config.DefaultCertOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to generate default certificate: %v", err)
		}
	}

	return store, nil
}

// AddHeader adds a header template for an upstream
func (p *Proxy) AddHeader(upstream, headerName, template string) error {
	return p.headerInjector.AddHeader(upstream, headerName, template)
}

// AddCommonHeader adds a common header (groups, roles, etc) for an upstream
func (p *Proxy) AddCommonHeader(headerType, upstream, headerName string) error {
	return p.headerInjector.AddCommonHeader(headerType, upstream, headerName)
}

// translateServerName converts an external domain name to its internal equivalent
func (p *Proxy) translateServerName(serverName string) string {
	// If the server name ends with external domain, replace it with internal domain
	if strings.HasSuffix(serverName, p.config.ExternalDomain) {
		return strings.TrimSuffix(serverName, p.config.ExternalDomain) + p.config.InternalDomain
	}
	return serverName
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

	// Check if it's an IP address
	if net.ParseIP(host) != nil {
		return ""
	}

	// For hostnames, use the hostname
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
		p.proxyLogger.Error("Failed to write error response: %v", err)
	}
}

// handleErrorConnection handles a connection that has encountered an error before proxying started
func (p *Proxy) handleErrorConnection(conn net.Conn, statusCode int, message string) {
	p.proxyLogger.Error("Connection error from %s: %s", conn.RemoteAddr(), message)
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
		p.proxyLogger.Error("Failed to write error response: %v", err)
	}
}



// HandleConnection manages a proxied connection with identity translation
func (p *Proxy) HandleConnection(conn net.Conn) {
	defer conn.Close()

	ident := &identity.Identity{}

	// Since we use tls.Listen, conn is already a *tls.Conn
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		p.proxyLogger.Error("Connection is not a TLS connection")
		p.handleErrorConnection(conn, http.StatusBadRequest, "internal server error")
		return
	}

	// Get connection state and verify client certificate if required
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		if !p.allowUnknownCerts {
			p.proxyLogger.Error("No client certificate provided")
			p.handleErrorConnection(conn, http.StatusBadRequest, "client certificate required")
			return
		}
		// Create a default identity for unknown clients
		ident = &identity.Identity{
			CommonName: "unknown",
			Roles:      []string{"anonymous"},
		}
		p.proxyLogger.Debug("No client certificate provided, using default identity: %v", ident)
	}

	// Translate identity from certificate if one was provided
	if len(state.PeerCertificates) > 0 {
		var err error
		ident, err = p.translator.TranslateIdentity(state.PeerCertificates[0])
		if err != nil {
			if !p.allowUnknownCerts {
				p.proxyLogger.Error("Failed to translate identity: %v", err)
				p.handleErrorConnection(conn, http.StatusBadRequest, "identity translation failed")
				return
			}
			// Fall back to default identity if translation fails and we allow unknown certs
			ident = &identity.Identity{
				CommonName: state.PeerCertificates[0].Subject.CommonName,
				Roles:      []string{"anonymous"},
			}
			p.proxyLogger.Debug("Identity translation failed, using cert CN as identity: %v", ident)
		}
	}

	// Get server name from TLS state
	serverName := state.ServerName

	// Resolve destination
	destination, err := p.router.ResolveDestination(serverName)
	if err != nil {
		p.handleErrorConnection(conn, http.StatusNotFound, err.Error())
		return
	}

	// Check if this is an HTTP connection that needs header injection
	// note we handleHTTPConnection even if InjectHeadersUpstream|Downstream are false
	if ok := p.headerInjector.HasHeaders(serverName, ident); ok {
		p.handleHTTPConnection(tlsConn, destination, serverName, ident)
		return
	}

	// Handle as TCP connection
	p.handleTCPConnection(conn, tlsConn, destination, ident)
}

// connResponseWriter adapts net.Conn to http.ResponseWriter
type connResponseWriter struct {
	conn    net.Conn
	header  http.Header
	written bool
}

func newConnResponseWriter(conn net.Conn) *connResponseWriter {
	return &connResponseWriter{
		conn:   conn,
		header: make(http.Header),
	}
}

func (w *connResponseWriter) Header() http.Header {
	return w.header
}

func (w *connResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.conn.Write(b)
}

func (w *connResponseWriter) WriteHeader(statusCode int) {
	if w.written {
		return
	}
	w.written = true

	// Write status line
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "status code " + fmt.Sprint(statusCode)
	}
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", statusCode, statusText)

	// Write headers
	w.header.Write(w.conn)

	// Write the final CRLF
	fmt.Fprintf(w.conn, "\r\n")
}

func (p *Proxy) handleHTTPConnection(conn net.Conn, destination string, serverName string, identity *identity.Identity) {
	// Note: conn is already a TLS connection established by setupTLSConnection
	defer conn.Close()

	p.proxyLogger.Debug("Starting HTTP connection handling for destination: %s, server: %s", destination, serverName)

	upstreamClientCert, err := p.internalCertStore.GetCertificate(context.Background(), identity.CommonName)
	if err != nil {
		p.proxyLogger.Error("Failed to get certificate for %s: %v", destination, err)
		return
	}

	// Configure TLS for the upstream connection
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
	}
	p.proxyLogger.Debug("Using host %s for TLS verification", host)
	p.proxyLogger.Debug("Using server name %s for TLS verification", serverName)

	// Create the reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = destination

			p.proxyLogger.Debug("Modifying request for upstream: %s %s", req.Method, req.URL)

			if p.config.InjectHeadersUpstream {
				headers, err := p.headerInjector.GetHeaders(serverName, identity)
				if err != nil {
					p.proxyLogger.Error("Failed to get headers: %v", err)
					return
				}

				for key, value := range headers {
					p.proxyLogger.Debug("Injecting header %q = %q", key, value)
					req.Header.Set(key, value)
				}
			}

			// Log final request headers
			p.proxyLogger.Debug("Final request headers:")
			for key, values := range req.Header {
				p.proxyLogger.Debug("  %s: %v", key, values)
			}
		},
		// Use a transport that will establish new TLS connections to the upstream
		Transport: &http.Transport{
			TLSClientConfig: p.createUpstreamTLSConfig(upstreamClientCert, p.translateServerName(serverName)),
		},
		ModifyResponse: func(resp *http.Response) error {
			if p.config.InjectHeadersDownstream {
				headers, err := p.headerInjector.GetHeaders(serverName, identity)
				if err != nil {
					return fmt.Errorf("failed to get headers: %v", err)
				}

				for key, value := range headers {
					p.proxyLogger.Debug("Injecting resp header %q = %q", key, value)
					resp.Header.Set(key, value)
				}
			}

			p.proxyLogger.Debug("Got response: %d %s", resp.StatusCode, resp.Status)
			p.proxyLogger.Debug("Response headers:")
			for key, values := range resp.Header {
				p.proxyLogger.Debug("  %s: %v", key, values)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.proxyLogger.Error("Proxy error: %v", err)

			// Try to send an error response if possible
			if !w.(*connResponseWriter).written {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte(fmt.Sprintf("Proxy Error: %v", err)))
			}
		},
	}

	// Create response writer that writes to our connection
	writer := newConnResponseWriter(conn)
	reader := bufio.NewReader(conn)

	// Read the request
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.proxyLogger.Error("Failed to read request: %v", err)
		return
	}

	// Set the Host header if not already set
	if req.Host == "" {
		req.Host = destination
	}

	// Serve the request
	proxy.ServeHTTP(writer, req)

	p.proxyLogger.Debug("Successfully completed proxy request")
}

// handleTCPConnection handles direct TCP proxying with TLS termination
func (p *Proxy) handleTCPConnection(conn net.Conn, tlsConn *tls.Conn, destination string, ident *identity.Identity) {
	// Get certificate for upstream connection
	var upstreamCert *tls.Certificate
	var err error = nil
	if ident.CommonName == tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName {
		// If we're using the auto-mapped identity, get cert by CN
		cn := ident.CommonName
		upstreamCert, err = p.internalCertStore.GetCertificate(context.Background(), cn)
		if err != nil {
			p.handleErrorConnection(conn, http.StatusInternalServerError, "Failed to get certificate")
			return
		}
		p.proxyLogger.Debug("Using auto-mapped certificate with CN: %s", cn)
	} else {
		upstreamCert, err = p.internalCertStore.GetCertificate(context.Background(), destination)
		if err != nil {
			p.handleErrorConnection(conn, http.StatusInternalServerError, "Failed to get certificate")
			return
		}
	}

	// Extract host from destination for TLS verification
	host := destination
	if h, _, err := net.SplitHostPort(destination); err == nil {
		host = h
	}

	// Create TLS config for upstream connection using cert store
	upstreamConfig := p.createUpstreamTLSConfig(upstreamCert, p.translateServerName(host))

	// If connecting to an echo server (a static route endpoint), use its name for TLS verification
	if echoName, echoAddr := p.router.GetEchoUpstream(); echoName != "" && destination == echoAddr {
		upstreamConfig.ServerName = echoName
	}

	// Connect to upstream
	upstreamConn, err := tls.Dial("tcp", destination, upstreamConfig)
	if err != nil {
		p.handleErrorConnection(conn, http.StatusInternalServerError, "Failed to connect to upstream")
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
		p.proxyLogger.Error("Error during TCP proxy: %v", err)
	}
}

// ListenAndServe starts the TLS proxy server
func (p *Proxy) ListenAndServe(config *Config) error {
	// Start echo server if enabled
	if config.EchoName != "" {
		if err := p.setupEchoServer(config); err != nil {
			return fmt.Errorf("failed to setup echo server: %v", err)
		}
	}

	// Create server TLS config
	tlsConfig, err := p.createServerTLSConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %v", err)
	}

	// Start TLS listener
	ln, err := tls.Listen("tcp", config.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener: %v", err)
	}
	defer ln.Close()

	p.proxyLogger.Info("listening on %s", config.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			p.proxyLogger.Error("Failed to accept connection: %v", err)
			continue
		}
		go p.HandleConnection(conn)
	}
}

// setupEchoServer configures and starts the echo server
func (p *Proxy) setupEchoServer(config *Config) error {
	if !strings.HasSuffix(config.EchoName, config.InternalDomain) {
		p.proxyLogger.Info("echo name does not have internal domain, adding: %s.%s", config.EchoName, config.InternalDomain)
		config.EchoName = fmt.Sprintf("%s.%s", config.EchoName, config.InternalDomain)
	}

	// Use provided echo cert options or create default ones
	var echoCertOptions *certstore.CertificateOptions
	if config.EchoDefaultCertOptions != nil {
		echoCertOptions = config.EchoDefaultCertOptions
	} else {
		echoCertOptions = &certstore.CertificateOptions{
			CommonName:  config.EchoName,
			DNSNames: []string{
				"localhost",
				config.EchoName,
				fmt.Sprintf("*.%s", config.InternalDomain),
			},
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			TTL:         config.EchoStoreConfig.DefaultTTL, // Use TTL from config
		}
	}

	// Get certificate from store using the provided echo name
	echoServerCert, err := p.internalCertStore.GetCertificateWithOptions(context.Background(), config.EchoName, echoCertOptions)
	if err != nil {
		return fmt.Errorf("failed to get echo server certificate: %v", err)
	}

	echoServer := echo.New(echoServerCert, p.internalCertStore.GetCertPool(), config.EchoName)
	if err := echoServer.Start(config.EchoAddr); err != nil {
		return fmt.Errorf("failed to start echo server: %v", err)
	}

	// Configure router to use echo server
	p.router.SetEchoUpstream(config.EchoName, config.EchoAddr)
	// Add static route from 'echo' to the full echo name for convenience
	p.router.AddStaticRoute("echo", config.EchoName)
	p.proxyLogger.Info("Echo upstream enabled as '%s' on %s with alias 'echo'", config.EchoName, config.EchoAddr)

	return nil
}

// createServerTLSConfig creates the TLS configuration for the proxy's server listener.
// This includes setting up server certificates, client certificate verification,
// and CA pools for verifying both client and upstream certificates.
func (p *Proxy) createServerTLSConfig(config *Config) (*tls.Config, error) {
	var serverCert *tls.Certificate

	// Use auto-generated certificates for the server
	genStore, ok := p.serverCertStore.(*certstore.GeneratedStore)
	if !ok {
		return nil, fmt.Errorf("server cert store is not a generated store")
	}

	// Configure server cert options
	serverOpts := &certstore.CertificateOptions{
		CommonName:  config.ServerName,
		DNSNames: []string{
			"localhost",
			config.ServerName,
			fmt.Sprintf("*.%s", config.ExternalDomain),
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		TTL:         365 * 24 * time.Hour, // 1 year
	}

	// Get or generate server certificate
	cert, err := genStore.GetCertificateWithOptions(context.Background(), config.ServerName, serverOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %v", err)
	}
	serverCert = cert

	// Configure client auth based on allowUnknownCerts setting
	// Set up client certificate verification
	clientAuth := tls.RequireAndVerifyClientCert
	var clientCAs *x509.CertPool
	if p.allowUnknownCerts {
		p.proxyLogger.Info("Client certificate verification disabled - accepting connections without certificates")
		clientAuth = tls.RequestClientCert // Allow but don't require client certs
		clientCAs = nil // Don't verify against any CA pool
	} else {
		clientCAs = p.serverCertStore.GetCertPool() // Verify against server CA pool
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,     // CA pool for verifying client certs (nil if allowUnknownCerts)
		RootCAs:      p.internalCertStore.GetCertPool(), // CA pool for verifying upstream server certs
	}

	// Configure client certificate verification
	if config.CAFile != "" {
		p.proxyLogger.Debug("Client certificate verification enabled - verifying client certificates against provided CA file")
		// Use provided CA file for client cert verification
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		tlsConfig.ClientCAs = caCertPool
	}

	return tlsConfig, nil
}

// createUpstreamTLSConfig creates a TLS configuration for upstream connections
func (p *Proxy) createUpstreamTLSConfig(upstreamCert *tls.Certificate, serverName string) *tls.Config {
	return &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert, // Always verify upstream client certs
		Certificates: []tls.Certificate{*upstreamCert},
		RootCAs:     p.internalCertStore.GetCertPool(), // Trust internal CA for upstream certs
		ClientCAs:   p.internalCertStore.GetCertPool(), // Trust internal CA for client certs
		ServerName:  serverName,
	}
}

// Translator returns the identity translator instance
func (p *Proxy) Translator() *identity.Translator {
	return p.translator
}

// AddStaticRoute adds a static route to the router
func (p *Proxy) AddStaticRoute(src, dest string) {
	if dest == p.config.EchoName {
		dest = fmt.Sprintf("%s.%s", dest, p.config.InternalDomain)
	}
	p.router.AddStaticRoute(src, dest)
}

// AddRoutes adds static routes from a comma-separated string
func (p *Proxy) AddRoutes(routes string) {
	for _, route := range strings.Split(routes, ",") {
		parts := strings.Split(route, "=")
		if len(parts) != 2 {
			p.proxyLogger.Error("Invalid route format: %s", route)
			continue
		}

		if parts[0] == p.config.EchoName {
			p.AddStaticRoute(fmt.Sprintf("%s.%s", parts[0], p.config.InternalDomain), parts[1]) // echo is a special case and will become echo.{internalDomain}
		} else {
			p.AddStaticRoute(parts[0], parts[1])
		}
	}
}
