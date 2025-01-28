package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/router"
)

// Proxy handles the connection proxying and identity translation
type Proxy struct {
	router            *router.Router
	translator        *identity.Translator
	certStore         certstore.Store
	allowUnknownCerts bool
}

// New creates a new proxy instance
func New(router *router.Router, translator *identity.Translator, store certstore.Store, allowUnknownCerts bool) *Proxy {
	return &Proxy{
		router:            router,
		translator:        translator,
		certStore:         store,
		allowUnknownCerts: allowUnknownCerts,
	}
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
func (p *Proxy) handleHTTPConnection(clientConn *tls.Conn, upstreamConn *tls.Conn, identities []identity.Identity) error {
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

	// Copy headers
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

	// Step 6: Create TLS config for upstream connection
	upstreamConfig := &tls.Config{
		Certificates: []tls.Certificate{*upstreamCert},
		ServerName:   destination,
	}

	// If connecting to echo server, use its name for TLS verification
	if echoName, echoAddr := p.router.GetEchoUpstream(); echoName != "" && destination == echoAddr {
		upstreamConfig.ServerName = "echo-server"
	}

	// Add root CA if using generated store
	if genStore, ok := p.certStore.(*certstore.GeneratedStore); ok {
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(genStore.GetCACertificate())
		upstreamConfig.RootCAs = rootCAs
	}

	// Step 7: All validation passed, now connect to upstream
	upstreamConn, err := tls.Dial("tcp", destination, upstreamConfig)
	if err != nil {
		p.handleErrorConnection(conn, http.StatusInternalServerError, fmt.Sprintf("Failed to connect to upstream: %v", err))
		return
	}
	defer upstreamConn.Close()

	// Step 8: Start proxying data
	if err := p.handleHTTPConnection(tlsConn, upstreamConn, identities); err != nil {
		p.handleErrorConnection(conn, http.StatusBadGateway, err.Error())
		return
	}
}
