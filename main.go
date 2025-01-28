package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"context"
	"crypto/tls"

	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/proxy"
	"github.com/itp/pkg/router"
)

func main() {
	log.Printf("starting Identity Translation Proxy")

	// TLS configuration flags
	certFile := flag.String("server-cert", "auto", "Server certificate file or 'auto' for auto-generated")
	keyFile := flag.String("server-key", "auto", "Server key file or 'auto' for auto-generated")
	caFile := flag.String("server-ca", "", "CA certificate file for server cert (only used with auto-generated certs)")
	addr := flag.String("addr", ":8443", "address for tls proxy server to listen on")
	certStoreType := flag.String("cert-store", "auto", "Certificate store type (k8s or auto)")

	// Routing flags
	routes := flag.String("route", "", "Static routes in format src=dest[,src=dest,...]")
	routePatterns := flag.String("route-pattern", "", "Route patterns in format src=dest[,src=dest,...]")
	useDNS := flag.Bool("dns", true, "Use DNS for routing")

	// Identity mapping flags
	cnMappings := flag.String("map-common-name", "", "Common name mappings in format src=identity[,src=identity,...]")
	orgMappings := flag.String("map-organization", "", "Organization mappings")
	countryMappings := flag.String("map-country", "", "Country mappings")
	stateMappings := flag.String("map-state", "", "State mappings")
	localityMappings := flag.String("map-locality", "", "Locality mappings")
	ouMappings := flag.String("map-organization-unit", "", "Organizational unit mappings")

	flag.Parse()

	// Initialize certificate store
	var store certstore.Store
	var serverCert *tls.Certificate
	
	switch *certStoreType {
	case "k8s":
		store = certstore.NewK8sStore(certstore.K8sOptions{
			Options: certstore.Options{
				CacheDuration: 1 * time.Hour,
				DefaultTTL:    24 * time.Hour,
			},
			Namespace: "default", // TODO: Add namespace flag if needed
			Client:    nil,       // TODO: Add k8s client initialization
		})
	case "auto":
		var err error
		store, err = certstore.NewGeneratedStore(certstore.GeneratedOptions{
			Options: certstore.Options{
				CacheDuration: 1 * time.Hour,
				DefaultTTL:    24 * time.Hour,
			},
		})
		if err != nil {
			log.Fatal("Failed to create auto certificate store:", err)
		}
	default:
		log.Fatalf("Unknown certificate store type: %s", *certStoreType)
	}

	// Initialize TLS config
	if *certFile == "auto" {
		// Use auto-generated certificates for the server
		genStore, ok := store.(*certstore.GeneratedStore)
		if !ok {
			log.Fatal("Auto server certificates require auto cert-store type")
		}

		// Load or create CA certificate
		var caCert *x509.Certificate
		if *caFile != "" {
			caBytes, err := os.ReadFile(*caFile)
			if err != nil {
				log.Fatalf("Failed to read CA file: %v", err)
			}
			block, _ := pem.Decode(caBytes)
			if block == nil {
				log.Fatal("Failed to decode CA PEM")
			}
			caCert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalf("Failed to parse CA certificate: %v", err)
			}
		} else {
			caCert = genStore.GetCACertificate()
		}

		// Save CA certificate if requested
		if *caFile != "" && !fileExists(*caFile) {
			caBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caCert.Raw,
			})
			if err := os.WriteFile(*caFile, caBytes, 0644); err != nil {
				log.Printf("Warning: Failed to save CA certificate to %s: %v", *caFile, err)
			}
		}

		// Generate server certificate
		cert, err := genStore.GetCertificate(context.Background(), "server")
		if err != nil {
			log.Fatalf("Failed to generate server certificate: %v", err)
		}
		serverCert = cert
	} else {
		// Use file-based certificates
		var err error
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to load server certificate: %v", err)
		}

		serverCert = &cert
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.RequestClientCert,
	}

	// Initialize router
	r := router.NewRouter(*useDNS)

	// Add static routes
	if *routes != "" {
		addRoutes(r, *routes)
	}

	// Add route patterns
	if *routePatterns != "" {
		addRoutePatterns(r, *routePatterns)
	}

	// Initialize identity translator
	t := identity.NewTranslator()

	// Add identity mappings
	addMappings(t, "common-name", *cnMappings)
	addMappings(t, "organization", *orgMappings)
	addMappings(t, "country", *countryMappings)
	addMappings(t, "state", *stateMappings)
	addMappings(t, "locality", *localityMappings)
	addMappings(t, "organization-unit", *ouMappings)

	// Create proxy
	p := proxy.New(r, t, store)

	// Start listener
	log.Printf("listening on %s", *addr)
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal("Failed to start listener:", err)
	}
	defer ln.Close()

	tlsListener := tls.NewListener(ln, tlsConfig)
	defer tlsListener.Close()

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			log.Println("Failed to accept connection:", err)
			continue
		}
		go p.HandleConnection(conn)
	}
}

// addMappings adds identity mappings from a comma-separated string
func addMappings(t *identity.Translator, field, mappings string) {
	if mappings == "" {
		return
	}

	for _, mapping := range strings.Split(mappings, ",") {
		parts := strings.Split(mapping, "=")
		if len(parts) == 2 {
			if err := t.AddMapping(field, parts[0], parts[1]); err != nil {
				log.Printf("Failed to add mapping for %s: %v", field, err)
			}
		}
	}
}

func addRoutes(r *router.Router, routes string) {
	for _, route := range strings.Split(routes, ",") {
		parts := strings.Split(route, "=")
		if len(parts) == 2 {
			r.AddStaticRoute(parts[0], parts[1])
		}
	}
}

func addRoutePatterns(r *router.Router, patterns string) {
	for _, pattern := range strings.Split(patterns, ",") {
		parts := strings.Split(pattern, "=")
		if len(parts) == 2 {
			r.AddRoutePattern(parts[0], parts[1])
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
