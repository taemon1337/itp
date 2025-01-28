package echo

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"
)

// ConnectionInfo contains details about the TLS connection
type ConnectionInfo struct {
	RemoteAddr    string   `json:"remote_addr"`
	LocalAddr     string   `json:"local_addr"`
	TLS           TLSInfo  `json:"tls"`
	Route         RouteInfo `json:"route"`
}

// TLSInfo contains TLS-specific connection details
type TLSInfo struct {
	Version               string   `json:"version"`
	CipherSuite          string   `json:"cipher_suite"`
	ServerName           string   `json:"server_name"`
	NegotiatedProtocol   string   `json:"negotiated_protocol"`
	ClientCertProvided   bool     `json:"client_cert_provided"`
	ClientCertSubject    string   `json:"client_cert_subject,omitempty"`
	ClientCertIssuer     string   `json:"client_cert_issuer,omitempty"`
	ClientCertNotBefore  string   `json:"client_cert_not_before,omitempty"`
	ClientCertNotAfter   string   `json:"client_cert_not_after,omitempty"`
}

// RouteInfo contains routing details
type RouteInfo struct {
	UpstreamName string `json:"upstream_name"`
}

// Server represents an echo server that reflects connection information
type Server struct {
	listener net.Listener
	cert     *tls.Certificate
	name     string
}

// New creates a new echo server
func New(cert *tls.Certificate, name string) *Server {
	return &Server{
		cert: cert,
		name: name,
	}
}

// Start starts the echo server on the specified address
func (s *Server) Start(addr string) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{*s.cert},
		ClientAuth:   tls.RequestClientCert,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	s.listener = tls.NewListener(ln, config)

	go s.serve()
	return nil
}

// Stop stops the echo server
func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("temporary accept error: %v", err)
				continue
			}
			log.Printf("accept error: %v", err)
			return
		}
		go s.handleConnection(conn)
	}
}

func getTLSVersion(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS_1.0"
	case tls.VersionTLS11:
		return "TLS_1.1"
	case tls.VersionTLS12:
		return "TLS_1.2"
	case tls.VersionTLS13:
		return "TLS_1.3"
	default:
		return "unknown"
	}
}

func getCipherSuiteName(id uint16) string {
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	return "unknown"
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Printf("connection is not TLS")
		return
	}

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}

	state := tlsConn.ConnectionState()

	info := ConnectionInfo{
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		TLS: TLSInfo{
			Version:             getTLSVersion(state.Version),
			CipherSuite:        getCipherSuiteName(state.CipherSuite),
			ServerName:         state.ServerName,
			NegotiatedProtocol: state.NegotiatedProtocol,
		},
		Route: RouteInfo{
			UpstreamName: s.name,
		},
	}

	// Add client certificate information if provided
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.TLS.ClientCertProvided = true
		info.TLS.ClientCertSubject = cert.Subject.String()
		info.TLS.ClientCertIssuer = cert.Issuer.String()
		info.TLS.ClientCertNotBefore = cert.NotBefore.Format(time.RFC3339)
		info.TLS.ClientCertNotAfter = cert.NotAfter.Format(time.RFC3339)
	}

	// Send connection info as pretty-printed JSON
	encoder := json.NewEncoder(conn)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(info); err != nil {
		log.Printf("failed to send connection info: %v", err)
		return
	}
}
