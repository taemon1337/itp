package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"

	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/router"
)

// Proxy handles the connection proxying and identity translation
type Proxy struct {
	router       *router.Router
	translator   *identity.Translator
	certStore    certstore.Store
}

// New creates a new proxy instance
func New(router *router.Router, translator *identity.Translator, store certstore.Store) *Proxy {
	return &Proxy{
		router:       router,
		translator:   translator,
		certStore:    store,
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
		log.Printf("Failed to resolve destination for %s: %v", sni, err)
		return
	}

	// Get certificate for upstream connection
	upstreamCert, err := p.certStore.GetCertificate(context.Background(), destination)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", destination, err)
		return
	}

	// Create subject for upstream connection
	subject := p.translator.GetSubjectFromIdentity(identities)
	log.Printf("translated identities: %v for subject: %v", identities, subject)

	// Create TLS config for upstream connection
	upstreamConfig := &tls.Config{
		Certificates: []tls.Certificate{*upstreamCert},
		ServerName:   destination,
	}

	// Connect to upstream
	upstreamConn, err := tls.Dial("tcp", destination, upstreamConfig)
	if err != nil {
		log.Printf("failed to connect to upstream: %v", err)
		return
	}
	defer upstreamConn.Close()

	// Proxy traffic between client and upstream
	go func() {
		io.Copy(conn, upstreamConn)
	}()
	io.Copy(upstreamConn, conn)
}
