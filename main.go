package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/itp/pkg/proxy"
	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/logger"
)

// stringSlice is a flag that can be specified multiple times
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	// Required flags
	serverName := flag.String("server-name", "", "Server name for the proxy (e.g., proxy.example.com)")
	externalDomain := flag.String("external-domain", "", "External domain for connections (e.g., external.com)")
	internalDomain := flag.String("internal-domain", "", "Internal domain for connections (e.g., internal.local)")

	// Optional flags
	listenAddr := flag.String("listen", ":8443", "Address to listen on")
	echoName := flag.String("echo-name", "", "Name for the echo server (defaults to echo.<internal-domain>)")
	echoAddr := flag.String("echo-addr", ":8444", "Address for the echo server")
	
	// Multiple value flags
	var routes stringSlice
	flag.Var(&routes, "route", "Route in the format src=dest (e.g., localhost=echo). Can be specified multiple times")
	
	// Template flags
	var templateFiles stringSlice
	flag.Var(&templateFiles, "template-file", "Template file in format name=filepath. Can be specified multiple times")
	
	var templateStrings stringSlice
	flag.Var(&templateStrings, "template", "Template string in format name=template. Can be specified multiple times")
	
	// Certificate flags
	certFile := flag.String("cert", "", "Path to certificate file")
	keyFile := flag.String("key", "", "Path to private key file")
	caFile := flag.String("ca", "", "Path to CA certificate file")
	useK8sCertManager := flag.Bool("k8s-cert-manager", false, "Use Kubernetes cert-manager instead of generated certificates")
	k8sNamespace := flag.String("k8s-namespace", "default", "Kubernetes namespace for cert-manager resources")
	k8sIssuerName := flag.String("k8s-issuer-name", "default-issuer", "Name of the cert-manager issuer to use")
	k8sIssuerKind := flag.String("k8s-issuer-kind", "ClusterIssuer", "Kind of the cert-manager issuer (ClusterIssuer or Issuer)")
	k8sIssuerGroup := flag.String("k8s-issuer-group", "cert-manager.io", "API group of the issuer")

	// Security flags
	allowUnknownCerts := flag.Bool("allow-unknown-certs", false, "Allow unknown client certificates")
	routeViaDNS := flag.Bool("route-via-dns", false, "Enable DNS-based routing")
	autoMapCN := flag.Bool("auto-map-cn", true, "Automatically map CommonName")

	// Logging flags
	debugLevel := flag.String("debug-level", "info", "Debug level (error, warn, info, debug)")

	// Header injection flags
	injectUpstream := flag.Bool("inject-headers-upstream", true, "Inject headers upstream")
	injectDownstream := flag.Bool("inject-headers-downstream", false, "Inject headers downstream")
	
	// Multiple value header flags
	var injectHeaders stringSlice
	flag.Var(&injectHeaders, "inject-header", "Header template in format 'upstream=header=template' (e.g., 'localhost=X-User={{.CommonName}}'). Can be specified multiple times")

	var injectHeaderTemplates stringSlice
	flag.Var(&injectHeaderTemplates, "inject-header-template", "Header using named template in format 'upstream=header=template-name' (e.g., 'localhost=X-User=user-info'). Can be specified multiple times")
	
	var roleMappings stringSlice
	flag.Var(&roleMappings, "add-role", "Role mapping in format 'cn=value=role1,role2' (e.g., 'cn=admin=admin-role'). Can be specified multiple times")
	
	var authMappings stringSlice
	flag.Var(&authMappings, "add-auth", "Auth mapping in format 'cn=value=auth1,auth2' (e.g., 'cn=*=read,write'). Can be specified multiple times")

	flag.Parse()

	// Validate required flags
	if *serverName == "" || *externalDomain == "" || *internalDomain == "" {
		fmt.Println("Error: server-name, external-domain, and internal-domain are required")
		flag.Usage()
		os.Exit(1)
	}

	// Parse debug level
	level, err := logger.ParseLevel(*debugLevel)
	if err != nil {
		fmt.Printf("Warning: invalid debug level '%s', using 'info': %v\n", *debugLevel, err)
		level = logger.LevelInfo
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

	// Configure certificates and cert store
	if *useK8sCertManager {
		config.WithK8sCertManager()
		// Get k8s client and cert-manager client
		k8sConfig, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("Failed to get k8s config: %v", err)
		}
		k8sClient, err := kubernetes.NewForConfig(k8sConfig)
		if err != nil {
			log.Fatalf("Failed to create k8s client: %v", err)
		}
		cmClient, err := cmclient.NewForConfig(k8sConfig)
		if err != nil {
			log.Fatalf("Failed to create cert-manager client: %v", err)
		}
		// Set k8s config
		config.WithK8sConfig(certstore.K8sOptions{
			Namespace:   *k8sNamespace,
			Client:      k8sClient,
			CMClient:    cmClient,
			IssuerName:  *k8sIssuerName,
			IssuerKind:  *k8sIssuerKind,
			IssuerGroup: *k8sIssuerGroup,
		})
	} else if *certFile != "" || *keyFile != "" || *caFile != "" {
		config.WithCertificates(*certFile, *keyFile, *caFile)
	}

	// Configure security settings
	config.AllowUnknownCerts = *allowUnknownCerts
	config.RouteViaDNS = *routeViaDNS
	config.AutoMapCN = *autoMapCN
	config.InjectHeadersUpstream = *injectUpstream
	config.InjectHeadersDownstream = *injectDownstream

	// Create and start proxy with debug level
	p, err := proxy.NewProxy(config, level)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Add templates from files
	for _, tf := range templateFiles {
		parts := strings.SplitN(tf, "=", 2)
		if len(parts) != 2 {
			log.Printf("Warning: invalid template file format %q, expected name=filepath", tf)
			continue
		}
		name, filepath := parts[0], parts[1]
		if err := p.AddTemplateFile(name, filepath); err != nil {
			log.Printf("Warning: failed to add template file %q: %v", name, err)
		}
	}

	// Add template strings
	for _, ts := range templateStrings {
		parts := strings.SplitN(ts, "=", 2)
		if len(parts) != 2 {
			log.Printf("Warning: invalid template format %q, expected name=template", ts)
			continue
		}
		name, tmpl := parts[0], parts[1]
		if err := p.AddTemplate(name, tmpl); err != nil {
			log.Printf("Warning: failed to add template %q: %v", name, err)
		}
	}

	// Add routes
	for _, route := range routes {
		parts := strings.SplitN(route, "=", 2)
		if len(parts) != 2 {
			log.Printf("Warning: invalid route format %q, expected src=dest", route)
			continue
		}
		src, dest := parts[0], parts[1]
		p.AddStaticRoute(src, dest)
	}

	// Add header templates
	for _, header := range injectHeaders {
		parts := strings.SplitN(header, "=", 3)
		if len(parts) != 3 {
			log.Printf("Warning: invalid header format %q, expected upstream=header=template", header)
			continue
		}
		upstream, header, template := parts[0], parts[1], parts[2]
		if err := p.AddHeader(upstream, header, template); err != nil {
			log.Printf("Warning: failed to add header template: %v", err)
		}
	}

	// Add header templates that reference named templates
	for _, header := range injectHeaderTemplates {
		parts := strings.SplitN(header, "=", 3)
		if len(parts) != 3 {
			log.Printf("Warning: invalid header template format %q, expected upstream=header=template-name", header)
			continue
		}
		upstream, header, templateName := parts[0], parts[1], parts[2]
		if err := p.AddHeaderTemplate(upstream, header, templateName); err != nil {
			log.Printf("Warning: failed to add header template: %v", err)
		}
	}

	// Add role mappings
	for _, mapping := range roleMappings {
		parts := strings.SplitN(mapping, "=", 3)
		if len(parts) != 3 {
			log.Printf("Warning: invalid role mapping format %q, expected cn=value=role1,role2", mapping)
			continue
		}
		roles := strings.Split(parts[2], ",")
		p.Translator().AddRoleMapping(parts[0], parts[1], roles)
	}

	// Add auth mappings
	for _, mapping := range authMappings {
		parts := strings.SplitN(mapping, "=", 3)
		if len(parts) != 3 {
			log.Printf("Warning: invalid auth mapping format %q, expected cn=value=auth1,auth2", mapping)
			continue
		}
		auths := strings.Split(parts[2], ",")
		p.Translator().AddAuthMapping(parts[0], parts[1], auths)
	}

	log.Printf("Starting proxy server on %s", config.ListenAddr)
	if err := p.ListenAndServe(config); err != nil {
		log.Fatalf("Proxy server failed: %v", err)
	}
}
