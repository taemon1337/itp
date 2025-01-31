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
	"net/http/httputil"
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
	config            *Config
	allowUnknownCerts bool
	headerInjector    *HeaderInjector
	logger           *logger.Logger
	rootCAs          *x509.CertPool
}

// Config represents TLS configuration options for the proxy
type Config struct {
	// Server TLS config
	CertFile           string
	KeyFile            string
	CAFile            string
	ServerName        string
	InternalDomain    string
	ExternalDomain    string
	CertOptions       certstore.CertificateOptions
	EchoCertOptions   certstore.CertificateOptions
	AllowUnknownCerts bool
	ListenAddr        string

	InjectHeadersDownstream bool // Inject headers into downstream request by to client
	InjectHeadersUpstream   bool // Inject headers into upstream request by to client

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
func New(config *Config) (*Proxy, error) {
	// Initialize certificate store
	store, err := createCertStore(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate store: %v", err)
	}

	// Initialize router with logger
	router := router.NewRouter(config.RouterLogger, config.RouteViaDNS)

	// Initialize translator with logger
	translator := identity.NewTranslator(config.TranslatorLogger, config.AutoMapCN)

	// Load root CAs
	rootCAs := x509.NewCertPool()
	if config.CAFile != "" {
		caBytes, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %v", err)
		}
		if !rootCAs.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
	}

	return &Proxy{
		router:            router,
		translator:        translator,
		certStore:         store,
		config:            config,
		allowUnknownCerts: config.AllowUnknownCerts,
		headerInjector:    NewHeaderInjector(),
		logger:           config.ProxyLogger,
		rootCAs:          rootCAs,
	}, nil
}

// AutoMapEnabled returns true if auto mapping is enabled
func (p *Proxy) AutoMapEnabled() bool {
	return p.config.AutoMapCN
}

// createCertStore creates a certificate store based on the configuration
func createCertStore(config *Config) (certstore.Store, error) {
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
func (p *Proxy) setupTLSConnection(conn net.Conn) (*tls.Conn, *identity.Identity, string, error) {
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
	ident, err := p.translator.TranslateIdentity(clientCert)
	if err != nil {
		var msg string
		if translationErr, ok := err.(*identity.TranslationError); ok {
			switch translationErr.Code {
			case identity.ErrNoIdentityMappings:
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

	return tlsConn, ident, state.ServerName, nil
}

// HandleConnection manages a proxied connection with identity translation
func (p *Proxy) HandleConnection(conn net.Conn) {
	defer conn.Close()

	// Setup TLS connection and translate identity
	tlsConn, ident, serverName, err := p.setupTLSConnection(conn)
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
	// note we handleHTTPConnection even if InjectHeadersUpstream|Downstream are false
	if ok := p.headerInjector.HasHeaders(serverName, ident); ok {
		p.handleHTTPConnection(conn, destination, serverName, ident)
		return
	}

	// Handle as TCP connection
	p.handleTCPConnection(conn, tlsConn, destination, ident)
}

func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		p.logger.Error("Connection is not TLS")
		return
	}

	// Perform handshake to get client certificate
	if err := tlsConn.Handshake(); err != nil {
		p.logger.Error("TLS handshake failed: %v", err)
		return
	}

	// Get client certificate
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		p.logger.Error("No client certificate found")
		return
	}

	clientCert := state.PeerCertificates[0]
	p.logger.Debug("Using verified client certificate from %s, subject: %s", conn.RemoteAddr().String(), clientCert.Subject.String())

	// Translate identity
	identity, err := p.translator.TranslateIdentity(clientCert)
	if err != nil {
		p.logger.Error("Failed to translate identity: %v", err)
		return
	}

	// Get server name from SNI
	serverName := state.ServerName
	if serverName == "" {
		p.logger.Error("No SNI header found")
		return
	}

	// Resolve destination
	p.logger.Debug("Resolving destination for server name: %s", serverName)
	destination, err := p.router.ResolveDestination(serverName)
	if err != nil {
		p.logger.Error("Failed to resolve destination: %v", err)
		return
	}

	// Handle the connection based on protocol
	p.handleHTTPConnection(conn, destination, serverName, identity)
}

// connResponseWriter adapts net.Conn to http.ResponseWriter
type connResponseWriter struct {
	conn     net.Conn
	header   http.Header
	written  bool
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
	defer conn.Close()

	p.logger.Debug("Starting HTTP connection handling for destination: %s, server: %s", destination, serverName)

	upstreamClientCert, err := p.certStore.GetCertificate(context.Background(), identity.CommonName)
	if err != nil {
		p.logger.Error("Failed to get certificate for %s: %v", destination, err)
		return
	}

	// Configure TLS for the upstream connection
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
	}
	p.logger.Debug("Using host %s for TLS verification", host)
	p.logger.Debug("Using server name %s for TLS verification", serverName)

	// Create the reverse proxy
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = destination

			p.logger.Debug("Modifying request for upstream: %s %s", req.Method, req.URL)
			
			if p.config.InjectHeadersUpstream {
				headers, err := p.headerInjector.GetHeaders(serverName, identity)
				if err != nil {
					p.logger.Error("Failed to get headers: %v", err)
					return
				}

				for key, value := range headers {
					p.logger.Debug("Injecting header %q = %q", key, value)
					req.Header.Set(key, value)
				}
			}

			// Log final request headers
			p.logger.Debug("Final request headers:")
			for key, values := range req.Header {
				p.logger.Debug("  %s: %v", key, values)
			}
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:   serverName,
				Certificates: []tls.Certificate{*upstreamClientCert},
				RootCAs:      p.certStore.GetCertPool(),
			},
		},
		ModifyResponse: func(resp *http.Response) error {
			if p.config.InjectHeadersDownstream {
				headers, err := p.headerInjector.GetHeaders(serverName, identity)
				if err != nil {
					return fmt.Errorf("failed to get headers: %v", err)
				}

				for key, value := range headers {
					p.logger.Debug("Injecting resp header %q = %q", key, value)
					resp.Header.Set(key, value)
				}
			}

			p.logger.Debug("Got response: %d %s", resp.StatusCode, resp.Status)
			p.logger.Debug("Response headers:")
			for key, values := range resp.Header {
				p.logger.Debug("  %s: %v", key, values)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logger.Error("Proxy error: %v", err)
			
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
		p.logger.Error("Failed to read request: %v", err)
		return
	}

	// Set the Host header if not already set
	if req.Host == "" {
		req.Host = destination
	}

	// Serve the request
	proxy.ServeHTTP(writer, req)

	p.logger.Debug("Successfully completed proxy request")
}

// handleTCPConnection handles direct TCP proxying with TLS termination
func (p *Proxy) handleTCPConnection(conn net.Conn, tlsConn *tls.Conn, destination string, ident *identity.Identity) {
	// Get certificate for upstream connection
	var upstreamCert *tls.Certificate
	var err error = nil
	if ident.CommonName == tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName {
		// If we're using the auto-mapped identity, get cert by CN
		cn := ident.CommonName
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

// ListenAndServe starts the TLS proxy server
func (p *Proxy) ListenAndServe(config *Config) error {
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
		go p.handleConnection(conn)
	}
}

// setupEchoServer configures and starts the echo server
func (p *Proxy) setupEchoServer(config *Config) error {
	if !strings.HasSuffix(config.EchoName, config.InternalDomain) {
		p.config.ProxyLogger.Info("echo name does not have internal domain, adding: %s.%s", config.EchoName, config.InternalDomain)
		config.EchoName = fmt.Sprintf("%s.%s", config.EchoName, config.InternalDomain)
	}

	// Get certificate from store using the provided echo name
	echoServerCert, err := p.certStore.GetCertificateWithOptions(context.Background(), config.EchoName, config.EchoCertOptions)
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
func (p *Proxy) createTLSConfig(config *Config) (*tls.Config, error) {
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
		if config.ServerName == "" {
			config.ServerName = config.ExternalDomain
			config.CertOptions.DNSNames = []string{"localhost",fmt.Sprintf("*.%s", config.InternalDomain), fmt.Sprintf("*.%s", config.ExternalDomain)}
		}
		if config.InternalDomain == "" {
			return nil, fmt.Errorf("internal domain is required for auto-generated certificates")
		}
		if config.ExternalDomain == "" {
			return nil, fmt.Errorf("external domain is required for auto-generated certificates")
		}
		cert, err := genStore.GetCertificateWithOptions(context.Background(), config.ServerName, config.CertOptions)
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
			p.config.ProxyLogger.Error("Invalid route format: %s", route)
			continue
		}

        if parts[0] == p.config.EchoName {
            p.AddStaticRoute(fmt.Sprintf("%s.%s", parts[0], p.config.InternalDomain), parts[1]) // echo is a special case and will become echo.{internalDomain}
        } else {
			p.AddStaticRoute(parts[0], parts[1])
		}
	}
}
