package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/itp/pkg/echo"
	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/router"
)

// Proxy handles the connection proxying and identity translation
type Proxy struct {
	router            *router.Router
	translator        *identity.Translator
	certStore         certstore.Store
	config            Config
	allowUnknownCerts bool
	headerInjector    *HeaderInjector
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
}

// New creates a new proxy instance with the given configuration
func New(config Config) (*Proxy, error) {
	// Initialize certificate store
	store, err := createCertStore(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate store: %v", err)
	}

	// Initialize router
	router := router.NewRouter(config.RouteViaDNS)

	// Initialize translator
	translator := identity.NewTranslator(config.AutoMapCN)

	return &Proxy{
		router:            router,
		translator:        translator,
		certStore:         store,
		config:            config,
		allowUnknownCerts: config.AllowUnknownCerts,
		headerInjector:    NewHeaderInjector(),
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
		log.Printf("Failed to write error response: %v", err)
	}
}

// handleErrorConnection handles a connection that has encountered an error before proxying started
func (p *Proxy) handleErrorConnection(conn net.Conn, statusCode int, message string) {
	log.Printf("Connection error from %s: %s", conn.RemoteAddr(), message)
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
		log.Printf("Failed to write error response: %v", err)
	}
}

// handleHTTPConnection handles HTTP-specific proxying, including header injection
func (p *Proxy) handleHTTPConnection(clientConn *tls.Conn, upstreamConn *tls.Conn, identities []identity.Identity, serverName string) error {
	// Read HTTP request from client
	req, err := http.ReadRequest(bufio.NewReader(clientConn))
	if err != nil {
		return fmt.Errorf("failed to read request: %v", err)
	}
	defer req.Body.Close()

	// Create upstream request
	upstreamReq := &http.Request{
		Method: req.Method,
		URL:    req.URL,
		Header: make(http.Header),
		Body:   req.Body,
		Host:   req.Host,
	}

	// Copy original headers
	for k, v := range req.Header {
		upstreamReq.Header[k] = v
	}

	// Add identity information as headers if available
	if len(identities) > 0 {
		id := identities[0]
		if id.CommonName != "" {
			upstreamReq.Header.Set("X-Client-CN", id.CommonName)
		}
		if len(id.Organization) > 0 {
			upstreamReq.Header.Set("X-Client-Organization", strings.Join(id.Organization, ","))
		}
		if len(id.OrganizationUnit) > 0 {
			upstreamReq.Header.Set("X-Client-OrganizationUnit", strings.Join(id.OrganizationUnit, ","))
		}
		if len(id.Locality) > 0 {
			upstreamReq.Header.Set("X-Client-Locality", strings.Join(id.Locality, ","))
		}
		if len(id.Country) > 0 {
			upstreamReq.Header.Set("X-Client-Country", strings.Join(id.Country, ","))
		}
		if len(id.State) > 0 {
			upstreamReq.Header.Set("X-Client-State", strings.Join(id.State, ","))
		}
	}

	// Add custom headers if configured for this destination
	destination, err := p.router.ResolveDestination(serverName)
	if err != nil {
		return fmt.Errorf("failed to resolve destination: %v", err)
	}
	for name, value := range p.headerInjector.GetHeaders(destination, identities) {
		if value != "" {
			upstreamReq.Header.Set(name, value)
		}
	}

	// Send request to upstream
	if err := upstreamReq.Write(upstreamConn); err != nil {
		return fmt.Errorf("failed to write request to upstream: %v", err)
	}

	// Read response from upstream
	resp, err := http.ReadResponse(bufio.NewReader(upstreamConn), req)
	if err != nil {
		return fmt.Errorf("failed to read response from upstream: %v", err)
	}
	defer resp.Body.Close()

	// Forward response to client
	if err := resp.Write(clientConn); err != nil {
		return fmt.Errorf("failed to write response to client: %v", err)
	}

	return nil
}

// HandleConnection manages a proxied connection with identity translation
func (p *Proxy) HandleConnection(conn net.Conn) {
	defer conn.Close()

	// Step 1: Validate TLS connection and perform handshake
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		p.handleErrorConnection(conn, http.StatusBadRequest, "Connection must be TLS")
		return
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
		p.handleErrorConnection(conn, http.StatusBadRequest, msg)
		return
	}

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		msg := fmt.Sprintf("TLS handshake not completed (SNI: %s)", sni)
		p.handleErrorConnection(conn, http.StatusBadRequest, msg)
		return
	}

	// If no SNI was provided, use a default based on the connection
	if state.ServerName == "" {
		state.ServerName = p.getDefaultSNI(conn)
		log.Printf("No SNI provided, using default: %s", state.ServerName)
	}

	// Step 2: Resolve destination
	destination, err := p.router.ResolveDestination(state.ServerName)
	if err != nil {
		if strings.Contains(err.Error(), "no route found") {
			p.handleErrorConnection(conn, http.StatusNotFound, fmt.Sprintf("No route found for %s", state.ServerName))
		} else {
			p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to resolve destination: %v", err))
		}
		return
	}

	// Step 3: Validate client certificate
	var clientCert *x509.Certificate
	if p.allowUnknownCerts {
		// When allowing unknown certs, use PeerCertificates directly
		if len(state.PeerCertificates) == 0 {
			msg := fmt.Sprintf("No client certificate provided (SNI: %s)", state.ServerName)
			p.handleErrorConnection(conn, http.StatusUnauthorized, msg)
			return
		}
		clientCert = state.PeerCertificates[0]
		log.Printf("Using unverified client certificate from %s, subject: %s",
			conn.RemoteAddr(), clientCert.Subject)
	} else {
		// When requiring verified certs, use VerifiedChains
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			msg := fmt.Sprintf("No verified client certificate chain (SNI: %s)", state.ServerName)
			p.handleErrorConnection(conn, http.StatusUnauthorized, msg)
			return
		}
		clientCert = state.VerifiedChains[0][0]
		log.Printf("Using verified client certificate from %s, subject: %s",
			conn.RemoteAddr(), clientCert.Subject)
	}

	// Step 4: Translate identity
	identities, err := p.translator.TranslateIdentity(clientCert)
	if err != nil {
		var msg string
		var statusCode int

		// Check if it's our custom translation error
		if translationErr, ok := err.(*identity.TranslationError); ok {
			switch translationErr.Code {
			case identity.ErrNoMappings:
				statusCode = http.StatusForbidden
				msg = fmt.Sprintf("Access denied: %s", translationErr.Message)
			case identity.ErrUnrecognizedClient:
				statusCode = http.StatusUnauthorized
				msg = fmt.Sprintf("Invalid certificate: %s", translationErr.Message)
			default:
				statusCode = http.StatusInternalServerError
				msg = fmt.Sprintf("Identity translation failed: %s", translationErr.Message)
			}
		} else {
			statusCode = http.StatusInternalServerError
			msg = fmt.Sprintf("Identity translation failed: %v", err)
		}

		p.handleErrorConnection(conn, statusCode, msg)
		return
	}

	// Step 5: Get certificate for upstream connection
	var upstreamCert *tls.Certificate
	if len(identities) == 1 && identities[0].CommonName == clientCert.Subject.CommonName {
		// If we're using the auto-mapped identity, get cert by CN
		cn := clientCert.Subject.CommonName
		upstreamCert, err = p.certStore.GetCertificate(context.Background(), cn)
		if err != nil {
			p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to get certificate for CN %s: %v", cn, err))
			return
		}
		log.Printf("Using auto-mapped certificate with CN: %s", cn)
	} else {
		upstreamCert, err = p.certStore.GetCertificate(context.Background(), destination)
		if err != nil {
			p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to get certificate for %s: %v", destination, err))
			return
		}
	}

	// Create subject for upstream connection
	subject := p.translator.GetSubjectFromIdentity(identities)
	log.Printf("Translated identities: %v for subject: %v", identities, subject)

	// Extract host from destination for TLS verification
	host := destination
	if h, _, err := net.SplitHostPort(destination); err == nil {
		host = h
	}

	// Step 6: Create TLS config for upstream connection using cert store
	upstreamConfig := p.certStore.GetTLSClientConfig(upstreamCert, certstore.TLSClientOptions{
		ServerName: host,
	})

	// If connecting to echo server, use its name for TLS verification
	if echoName, echoAddr := p.router.GetEchoUpstream(); echoName != "" && destination == echoAddr {
		upstreamConfig.ServerName = echoName
	}

	// Step 7: All validation passed, now connect to upstream
	upstreamConn, err := tls.Dial("tcp", destination, upstreamConfig)
	if err != nil {
		p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to connect to upstream: %v", err))
		return
	}
	defer upstreamConn.Close()

	// Step 8: Start proxying data
	if err := p.handleHTTPConnection(tlsConn, upstreamConn, identities, state.ServerName); err != nil {
		p.handleErrorConnection(conn, http.StatusBadGateway, err.Error())
		return
	}
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

	log.Printf("listening on %s", config.ListenAddr)

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
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

	echoServer := echo.New(echoServerCert, config.EchoName)
	if err := echoServer.Start(config.EchoAddr); err != nil {
		return fmt.Errorf("failed to start echo server: %v", err)
	}

	// Configure router to use echo server
	p.router.SetEchoUpstream(config.EchoName, config.EchoAddr)
	log.Printf("Echo upstream enabled as '%s' on %s", config.EchoName, config.EchoAddr)

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
					log.Printf("Warning: Failed to save CA certificate to %s: %v", config.CAFile, err)
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
			log.Printf("Invalid route format: %s", route)
			continue
		}
		p.AddStaticRoute(parts[0], parts[1])
	}
}
