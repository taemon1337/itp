package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/echo"
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
	allowUnknownClients := flag.Bool("server-allow-unknown-client-certs", false, "Allow client certificates from unknown CAs")
	mapAuto := flag.Bool("map-auto", false, "Automatically map client CN to upstream CN")
	addr := flag.String("addr", ":8443", "address for tls proxy server to listen on")
	certStoreType := flag.String("cert-store", "auto", "Certificate store type (k8s or auto)")
	echoName := flag.String("echo", "", "Name for the echo upstream (e.g. 'echo' to use in --route src=echo)")
	echoAddr := flag.String("echo-addr", ":8444", "Address for echo upstream server")

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

	// Conditional role mapping flags
	rolesToCN := flag.String("add-role-to-cn", "", "Add roles when CN matches, format: cn=role1,role2[;cn=role1,role2,...]")
	rolesToOrg := flag.String("add-role-to-org", "", "Add roles when Organization matches, format: org=role1,role2[;org=role1,role2,...]")
	rolesToOU := flag.String("add-role-to-ou", "", "Add roles when OU matches, format: ou=role1,role2[;ou=role1,role2,...]")

	// Conditional group mapping flags
	groupsToCN := flag.String("add-group-to-cn", "", "Add groups when CN matches, format: cn=group1,group2[;cn=group1,group2,...]")
	groupsToOrg := flag.String("add-group-to-org", "", "Add groups when Organization matches, format: org=group1,group2[;org=group1,group2,...]")
	groupsToOU := flag.String("add-group-to-ou", "", "Add groups when OU matches, format: ou=group1,group2[;ou=group1,group2,...]")

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
		s, err := certstore.NewGeneratedStore(certstore.GeneratedOptions{
			CommonName: "itp",
			Expiry: 24 * time.Hour,
			DefaultTTL: 24 * time.Hour,
			CacheDuration: time.Hour,
		})
		if err != nil {
			log.Fatalf("Failed to create generated certificate store: %v", err)
		}
		store = s
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

	if !*allowUnknownClients {
		// Only verify client certs if we're not allowing unknown clients
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		if *caFile != "" {
			// Load CA cert if provided
			caCert, err := os.ReadFile(*caFile)
			if err != nil {
				log.Fatalf("Failed to read CA cert: %v", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				log.Fatalf("Failed to parse CA cert")
			}
			tlsConfig.ClientCAs = caCertPool
		}
	}

	// Initialize router
	r := router.NewRouter(*useDNS)

	// Start echo server if enabled
	if *echoName != "" {
		// Get certificate from store
		echoServerCert, err := store.GetCertificate(context.Background(), *echoAddr)
		if err != nil {
			log.Fatalf("Failed to get echo server certificate: %v", err)
		}

		echoServer := echo.New(echoServerCert, *echoName)
		if err := echoServer.Start(*echoAddr); err != nil {
			log.Fatalf("Failed to start echo server: %v", err)
		}
		defer echoServer.Stop()
		
		// Configure router to use echo server
		r.SetEchoUpstream(*echoName, *echoAddr)
		log.Printf("Echo upstream enabled as '%s' on %s", *echoName, *echoAddr)
	}

	// Add static routes
	if *routes != "" {
		addRoutes(r, *routes)
	}

	// Add route patterns
	if *routePatterns != "" {
		addRoutePatterns(r, *routePatterns)
	}

	// Create translator
	translator := identity.NewTranslator(*mapAuto)

	// Add identity mappings
	addMappings(translator, "common-name", *cnMappings)
	addMappings(translator, "organization", *orgMappings)
	addMappings(translator, "organization-unit", *ouMappings)
	addMappings(translator, "country", *countryMappings)
	addMappings(translator, "state", *stateMappings)
	addMappings(translator, "locality", *localityMappings)

	// Add conditional role mappings
	addRoleMappings(translator, "common-name", *rolesToCN)
	addRoleMappings(translator, "organization", *rolesToOrg)
	addRoleMappings(translator, "organization-unit", *rolesToOU)

	// Add conditional group mappings
	addGroupMappings(translator, "common-name", *groupsToCN)
	addGroupMappings(translator, "organization", *groupsToOrg)
	addGroupMappings(translator, "organization-unit", *groupsToOU)

	// Create proxy instance
	p := proxy.New(r, translator, store, *allowUnknownClients)

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
		if len(parts) != 2 {
			log.Printf("Invalid mapping format: %s", mapping)
			continue
		}
		t.AddMapping(field, parts[0], parts[1])
	}
}

// addRoleMappings adds role mappings from a semicolon-separated string
func addRoleMappings(t *identity.Translator, field, mappings string) {
	if mappings == "" {
		return
	}

	for _, mapping := range strings.Split(mappings, ";") {
		parts := strings.Split(mapping, "=")
		if len(parts) != 2 {
			log.Printf("Invalid role mapping format: %s", mapping)
			continue
		}

		sourceValue := parts[0]
		roles := strings.Split(parts[1], ",")
		t.AddRoleMapping(field, sourceValue, roles)
	}
}

// addGroupMappings adds group mappings from a semicolon-separated string
func addGroupMappings(t *identity.Translator, field, mappings string) {
	if mappings == "" {
		return
	}

	for _, mapping := range strings.Split(mappings, ";") {
		parts := strings.Split(mapping, "=")
		if len(parts) != 2 {
			log.Printf("Invalid group mapping format: %s", mapping)
			continue
		}

		sourceValue := parts[0]
		groups := strings.Split(parts[1], ",")
		t.AddGroupMapping(field, sourceValue, groups)
	}
}

// addRoutes adds static routes from a comma-separated string
func addRoutes(r *router.Router, routes string) {
	for _, route := range strings.Split(routes, ",") {
		parts := strings.Split(route, "=")
		if len(parts) != 2 {
			log.Printf("Invalid route format: %s", route)
			continue
		}
		r.AddStaticRoute(parts[0], parts[1])
	}
}

// addRoutePatterns adds route patterns from a comma-separated string
func addRoutePatterns(r *router.Router, patterns string) {
	for _, pattern := range strings.Split(patterns, ",") {
		parts := strings.Split(pattern, "=")
		if len(parts) != 2 {
			log.Printf("Invalid route pattern format: %s", pattern)
			continue
		}
		r.AddRoutePattern(parts[0], parts[1])
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
