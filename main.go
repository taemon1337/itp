package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/itp/pkg/proxy"
)

func main() {
	// Required flags
	serverName := flag.String("server-name", "", "Server name for the proxy (e.g., proxy.example.com)")
	externalDomain := flag.String("external-domain", "", "External domain for connections (e.g., external.com)")
	internalDomain := flag.String("internal-domain", "", "Internal domain for connections (e.g., internal.local)")

	// Optional flags
	listenAddr := flag.String("listen", ":8443", "Address to listen on")
	echoName := flag.String("echo-name", "", "Name for the echo server (defaults to echo.<internal-domain>)")
	echoAddr := flag.String("echo-addr", ":8444", "Address for the echo server")
	routes := flag.String("routes", "", "Comma-separated list of routes in the format src=dest (e.g., localhost=echo,app=app.internal)")
	
	// Certificate flags
	certFile := flag.String("cert", "", "Path to certificate file")
	keyFile := flag.String("key", "", "Path to private key file")
	caFile := flag.String("ca", "", "Path to CA certificate file")

	// Security flags
	allowUnknownCerts := flag.Bool("allow-unknown-certs", false, "Allow unknown client certificates")
	routeViaDNS := flag.Bool("route-via-dns", false, "Enable DNS-based routing")
	autoMapCN := flag.Bool("auto-map-cn", true, "Automatically map CommonName")

	// Header injection flags
	injectUpstream := flag.Bool("inject-headers-upstream", true, "Inject headers upstream")
	injectDownstream := flag.Bool("inject-headers-downstream", false, "Inject headers downstream")
	injectHeader := flag.String("inject-header", "", "Header template in format 'upstream=header=template' (e.g., 'localhost=X-User={{.CommonName}}')")
	addRoleMapping := flag.String("add-role", "", "Role mapping in format 'cn=value=role1,role2' (e.g., 'cn=admin=admin-role')")
	addAuthMapping := flag.String("add-auth", "", "Auth mapping in format 'cn=value=auth1,auth2' (e.g., 'cn=*=read,write')")

	flag.Parse()

	// Validate required flags
	if *serverName == "" || *externalDomain == "" || *internalDomain == "" {
		fmt.Println("Error: server-name, external-domain, and internal-domain are required")
		flag.Usage()
		os.Exit(1)
	}

	// Create base config
	config := proxy.NewProxyConfig(*serverName, *externalDomain, *internalDomain)

	// Configure optional settings
	config.ListenAddr = *listenAddr
	config.EchoAddr = *echoAddr

	// Configure echo server if name provided
	if *echoName != "" {
		config.WithEchoServer(*echoName)
	}

	// Configure certificates if provided
	if *certFile != "" || *keyFile != "" || *caFile != "" {
		config.WithCertificates(*certFile, *keyFile, *caFile)
	}

	// Configure security settings
	config.AllowUnknownCerts = *allowUnknownCerts
	config.RouteViaDNS = *routeViaDNS
	config.AutoMapCN = *autoMapCN
	config.InjectHeadersUpstream = *injectUpstream
	config.InjectHeadersDownstream = *injectDownstream

	// Create and start proxy
	p, err := proxy.NewProxy(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Add routes if provided
	if *routes != "" {
		p.AddRoutes(*routes)
	}

	// Add header templates if provided
	if *injectHeader != "" {
		parts := strings.SplitN(*injectHeader, "=", 3)
		if len(parts) == 3 {
			upstream, header, template := parts[0], parts[1], parts[2]
			if err := p.AddHeader(upstream, header, template); err != nil {
				log.Printf("Warning: failed to add header template: %v", err)
			}
		}
	}

	// Add role mappings if provided
	if *addRoleMapping != "" {
		parts := strings.SplitN(*addRoleMapping, "=", 3)
		if len(parts) == 3 {
			roles := strings.Split(parts[2], ",")
			p.Translator().AddRoleMapping(parts[0], parts[1], roles)
		}
	}

	// Add auth mappings if provided
	if *addAuthMapping != "" {
		parts := strings.SplitN(*addAuthMapping, "=", 3)
		if len(parts) == 3 {
			auths := strings.Split(parts[2], ",")
			p.Translator().AddAuthMapping(parts[0], parts[1], auths)
		}
	}

	log.Printf("Starting proxy server on %s", config.ListenAddr)
	if err := p.ListenAndServe(config); err != nil {
		log.Fatalf("Proxy server failed: %v", err)
	}
}
