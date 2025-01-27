package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/router"
)

// Proxy handles the connection proxying and identity translation
type Proxy struct {
	router       *router.Router
	translator   *identity.Translator
	upstreamAddr string
}

// New creates a new proxy instance
func New(router *router.Router, translator *identity.Translator, upstreamAddr string) *Proxy {
	return &Proxy{
		router:       router,
		translator:   translator,
		upstreamAddr: upstreamAddr,
	}
}

// HandleConnection manages a proxied connection with identity translation
func (p *Proxy) HandleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("conn is not tls: %s", conn)
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		log.Printf("tls handshake not completed: %s", state)
		return
	}

	// Get client certificate
	if len(state.PeerCertificates) == 0 {
		log.Printf("no client certificate provided")
		return
	}
	clientCert := state.PeerCertificates[0]

	// Translate identity
	identities, err := p.translator.TranslateIdentity(clientCert)
	if err != nil {
		log.Printf("failed to translate identity: %v", err)
		return
	}

	// Get SNI and resolve destination
	sni := state.ServerName
	if sni == "" {
		log.Printf("no SNI provided")
		return
	}

	destination, err := p.router.ResolveDestination(sni)
	if err != nil {
		log.Printf("failed to resolve destination: %v", err)
		return
	}

	// Create subject for upstream connection
	subject := p.translator.GetSubjectFromIdentity(identities)
	log.Printf("translated identities: %v for subject: %v", identities, subject)

	// Configure upstream TLS connection
	upstreamConfig := &tls.Config{
		ServerName: destination,
		// Additional TLS configuration for upstream connection would go here
	}

	// Establish TLS connection to upstream server
	upstreamConn, err := tls.Dial("tcp", p.upstreamAddr, upstreamConfig)
	if err != nil {
		log.Printf("failed to connect to upstream: %v", err)
		return
	}
	defer upstreamConn.Close()

	// Proxy traffic between client and upstream
	go func() {
		log.Printf("streaming conn...")
		io.Copy(conn, upstreamConn)
	}()
	io.Copy(upstreamConn, conn)
}
