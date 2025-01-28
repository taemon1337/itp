package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"

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

// HandleConnection manages a proxied connection with identity translation
func (p *Proxy) HandleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("Connection from %s is not TLS", conn.RemoteAddr())
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
		if sni != "" {
			log.Printf("TLS handshake failed for connection from %s, SNI: %s, error: %v",
				conn.RemoteAddr(), sni, err)
		} else {
			log.Printf("TLS handshake failed for connection from %s, no SNI provided, error: %v",
				conn.RemoteAddr(), err)
		}
		return
	}

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		log.Printf("TLS handshake not completed for connection from %s, SNI: %s",
			conn.RemoteAddr(), sni)
		return
	}

	// If no SNI was provided, use a default based on the connection
	if state.ServerName == "" {
		state.ServerName = p.getDefaultSNI(conn)
		log.Printf("No SNI provided, using default: %s", state.ServerName)
	}

	// Get client certificate
	var clientCert *x509.Certificate
	if p.allowUnknownCerts {
		// When allowing unknown certs, use PeerCertificates directly
		if len(state.PeerCertificates) == 0 {
			log.Printf("No client certificate provided for connection from %s, SNI: %s",
				conn.RemoteAddr(), state.ServerName)
			return
		}
		clientCert = state.PeerCertificates[0]
		log.Printf("Using unverified client certificate from %s, subject: %s",
			conn.RemoteAddr(), clientCert.Subject)
	} else {
		// When requiring verified certs, use VerifiedChains
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			log.Printf("No verified client certificate chain for connection from %s, SNI: %s",
				conn.RemoteAddr(), state.ServerName)
			return
		}
		clientCert = state.VerifiedChains[0][0]
		log.Printf("Using verified client certificate from %s, subject: %s",
			conn.RemoteAddr(), clientCert.Subject)
	}

	// Translate identity
	identities, err := p.translator.TranslateIdentity(clientCert)
	if err != nil {
		log.Printf("Failed to translate identity: %v", err)
		return
	}

	// Get destination from router
	destination, err := p.router.ResolveDestination(state.ServerName)
	if err != nil {
		log.Printf("Failed to resolve destination for %s: %v", state.ServerName, err)
		return
	}

	// Get certificate for upstream connection
	var upstreamCert *tls.Certificate
	if len(identities) == 1 && identities[0].CommonName == clientCert.Subject.CommonName {
		// If we're using the auto-mapped identity, get cert by CN
		cn := clientCert.Subject.CommonName
		upstreamCert, err = p.certStore.GetCertificate(context.Background(), cn)
		if err != nil {
			log.Printf("Failed to get certificate for CN %s: %v", cn, err)
			return
		}
		log.Printf("Using auto-mapped certificate with CN: %s", cn)
	} else {
		upstreamCert, err = p.certStore.GetCertificate(context.Background(), destination)
		if err != nil {
			log.Printf("Failed to get certificate for %s: %v", destination, err)
			return
		}
	}

	// Create subject for upstream connection
	subject := p.translator.GetSubjectFromIdentity(identities)
	log.Printf("Translated identities: %v for subject: %v", identities, subject)

	// Create TLS config for upstream connection
	upstreamConfig := &tls.Config{
		Certificates: []tls.Certificate{*upstreamCert},
		ServerName:   destination,
	}

	// Add root CA if using generated store
	if genStore, ok := p.certStore.(*certstore.GeneratedStore); ok {
		rootCAs := x509.NewCertPool()
		rootCAs.AddCert(genStore.GetCACertificate())
		upstreamConfig.RootCAs = rootCAs
	}

	// Connect to upstream
	upstreamConn, err := tls.Dial("tcp", destination, upstreamConfig)
	if err != nil {
		log.Printf("Failed to connect to upstream %s: %v", destination, err)
		return
	}
	defer upstreamConn.Close()

	// Copy data between connections
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstreamConn, tlsConn)
		errChan <- fmt.Errorf("error copying to upstream: %w", err)
	}()
	go func() {
		_, err := io.Copy(tlsConn, upstreamConn)
		errChan <- fmt.Errorf("error copying from upstream: %w", err)
	}()

	// Wait for first error
	err = <-errChan
	if err != nil && err.Error() != "error copying to upstream: EOF" &&
		err.Error() != "error copying from upstream: EOF" {
		log.Printf("Connection error for %s: %v", destination, err)
	}
}
