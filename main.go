package main

import (
	"flag"
	"log"
	"net"
	"strings"

	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/proxy"
	"github.com/itp/pkg/router"
	"github.com/itp/pkg/tls"
)

func main() {
	log.Printf("starting Identity Translation Proxy")

	// TLS configuration flags
	certFile := flag.String("cert", "server.crt", "Server certificate file")
	keyFile := flag.String("key", "server.key", "Server key file")
	caFile := flag.String("ca", "ca.crt", "CA chain file")
	addr := flag.String("addr", ":8443", "address for tls proxy server to listen on")

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

	// Initialize TLS config
	tlsConfig, err := tls.NewTLSConfig(tls.Config{
		CertFile: *certFile,
		KeyFile:  *keyFile,
		CAFile:   *caFile,
	})
	if err != nil {
		log.Fatal("Failed to create TLS config:", err)
	}

	// Initialize router
	r := router.NewRouter(*useDNS)

	// Add static routes
	if *routes != "" {
		for _, route := range strings.Split(*routes, ",") {
			parts := strings.Split(route, "=")
			if len(parts) == 2 {
				r.AddStaticRoute(parts[0], parts[1])
			}
		}
	}

	// Add route patterns
	if *routePatterns != "" {
		for _, pattern := range strings.Split(*routePatterns, ",") {
			parts := strings.Split(pattern, "=")
			if len(parts) == 2 {
				r.AddRoutePattern(parts[0], parts[1])
			}
		}
	}

	// Initialize identity translator
	t := identity.NewTranslator()

	// Add identity mappings
	addMappings(t, "CN", *cnMappings)
	addMappings(t, "O", *orgMappings)
	addMappings(t, "C", *countryMappings)
	addMappings(t, "ST", *stateMappings)
	addMappings(t, "L", *localityMappings)
	addMappings(t, "OU", *ouMappings)

	// Create proxy
	p := proxy.New(r, t)

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
		log.Printf("accept")
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
