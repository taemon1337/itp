package echo

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// ConnectionInfo contains details about the TLS connection
type ConnectionInfo struct {
	RemoteAddr string    `json:"remote_addr"`
	LocalAddr  string    `json:"local_addr"`
	TLS        TLSInfo   `json:"tls"`
	Route      RouteInfo `json:"route"`
}

// TLSInfo contains TLS-specific connection details
type TLSInfo struct {
	Version             string `json:"version"`
	CipherSuite         string `json:"cipher_suite"`
	ServerName          string `json:"server_name"`
	NegotiatedProtocol  string `json:"negotiated_protocol"`
	ClientCertProvided  bool   `json:"client_cert_provided"`
	ClientCertSubject   string `json:"client_cert_subject,omitempty"`
	ClientCertIssuer    string `json:"client_cert_issuer,omitempty"`
	ClientCertNotBefore string `json:"client_cert_not_before,omitempty"`
	ClientCertNotAfter  string `json:"client_cert_not_after,omitempty"`
}

// RouteInfo contains routing details
type RouteInfo struct {
	UpstreamName string      `json:"upstream_name"`
	Request      RequestInfo `json:"request"`
}

type RequestInfo struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Host    string      `json:"host"`
	Headers http.Header `json:"headers"`
}

// Server represents an echo server that reflects connection information
type Server struct {
	listener net.Listener
	cert     *tls.Certificate
	ca       *x509.CertPool
	name     string
}

// New creates a new echo server
func New(cert *tls.Certificate, ca *x509.CertPool, name string) *Server {
	return &Server{
		cert: cert,
		ca:   ca,
		name: name,
	}
}

// Start starts the echo server on the specified address
func (s *Server) Start(addr string) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{*s.cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    s.ca,
		RootCAs:      s.ca,
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

	// Create buffered reader and writer
	reader := bufio.NewReader(tlsConn)
	writer := bufio.NewWriter(tlsConn)

	// Read HTTP request
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("failed to read request: %v", err)
		return
	}
	log.Printf("[ECHO] request: %s %s %s (from %s)", req.Method, req.URL.Path, req.Host, conn.RemoteAddr())

	state := tlsConn.ConnectionState()

	info := ConnectionInfo{
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		TLS: TLSInfo{
			Version:            getTLSVersion(state.Version),
			CipherSuite:        getCipherSuiteName(state.CipherSuite),
			ServerName:         state.ServerName,
			NegotiatedProtocol: state.NegotiatedProtocol,
		},
		Route: RouteInfo{
			UpstreamName: s.name,
			Request: RequestInfo{
				Method:  req.Method,
				Path:    req.URL.Path,
				Host:    req.Host,
				Headers: req.Header,
			},
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

	// Convert info to JSON
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		log.Printf("failed to marshal connection info: %v", err)
		return
	}

	// Create HTTP response
	resp := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{fmt.Sprintf("%d", len(jsonData))},
			"Connection":     []string{"close"},
		},
		Body:          io.NopCloser(bytes.NewReader(jsonData)),
		ContentLength: int64(len(jsonData)),
	}

	// Send response using buffered writer
	if err := resp.Write(writer); err != nil {
		log.Printf("failed to write response: %v", err)
		return
	}

	// Flush the buffered writer
	if err := writer.Flush(); err != nil {
		log.Printf("failed to flush response: %v", err)
		return
	}

	log.Printf("[ECHO] sent response: %d bytes", len(jsonData))
}
