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
	"github.com/itp/pkg/config"
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
	// Config file flag
	configFile := flag.String("config", "", "Path to YAML configuration file")

	// Required flags (if not using config file)
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

	// Parse debug level
	level, err := logger.ParseLevel(*debugLevel)
	if err != nil {
		fmt.Printf("Warning: invalid debug level '%s', using 'info': %v\n", *debugLevel, err)
		level = logger.LevelInfo
	}

	// Create a new proxy config
	var proxyConfig *proxy.Config
	// Store the YAML config if loaded from file
	var yamlConfig *config.Config

	// Load configuration from file if specified
	if *configFile != "" {
		var err error
		yamlConfig, err = config.LoadFromFile(*configFile)
		if err != nil {
			fmt.Printf("Error loading config file: %v\n", err)
			os.Exit(1)
		}
		proxyConfig = yamlConfig.ToProxyConfig()
	} else {
		// Validate required flags when not using config file
		if *serverName == "" || *externalDomain == "" || *internalDomain == "" {
			fmt.Println("Error: server-name, external-domain, and internal-domain are required when not using a config file")
			flag.Usage()
			os.Exit(1)
		}

		// Create config from command line flags
		proxyConfig = proxy.NewProxyConfig(*serverName, *externalDomain, *internalDomain)
		proxyConfig.ListenAddr = *listenAddr
		proxyConfig.EchoName = *echoName
		proxyConfig.EchoAddr = *echoAddr
	}

	// Configure certificates if using command line flags
	if *configFile == "" {
		if *useK8sCertManager {
			proxyConfig.UseK8sCertManager = true
			proxyConfig.K8sStoreConfig = &certstore.K8sOptions{
				Namespace:   *k8sNamespace,
				IssuerName:  *k8sIssuerName,
				IssuerKind:  *k8sIssuerKind,
				IssuerGroup: *k8sIssuerGroup,
			}
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
			// Set k8s clients in config
			proxyConfig.K8sStoreConfig.Client = k8sClient
			proxyConfig.K8sStoreConfig.CMClient = cmClient
		} else if *certFile != "" {
			proxyConfig.WithCertificates(*certFile, *keyFile, *caFile)
		}

		// Configure security settings
		proxyConfig.AllowUnknownCerts = *allowUnknownCerts
		proxyConfig.RouteViaDNS = *routeViaDNS
		proxyConfig.AutoMapCN = *autoMapCN
		proxyConfig.InjectHeadersUpstream = *injectUpstream
		proxyConfig.InjectHeadersDownstream = *injectDownstream
	}

	// Create proxy
	p, err := proxy.NewProxy(proxyConfig, level)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Add routes and templates from command line if not using config file
	if *configFile == "" {
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
	} else {
		// Add routes from config file
		for _, route := range yamlConfig.Routes {
			p.AddStaticRoute(route.Source, route.Destination)
		}

		// Add templates from config file
		for _, tmpl := range yamlConfig.Templates.Files {
			if err := p.AddTemplateFile(tmpl.Name, tmpl.Path); err != nil {
				log.Printf("Warning: failed to add template file '%s': %v\n", tmpl.Name, err)
			}
		}

		for _, tmpl := range yamlConfig.Templates.Inline {
			if err := p.AddTemplate(tmpl.Name, tmpl.Template); err != nil {
				log.Printf("Warning: failed to add template '%s': %v\n", tmpl.Name, err)
			}
		}

		// Add headers from config file
		for _, header := range yamlConfig.Headers.Templates {
			if err := p.AddHeader(header.Upstream, header.Header, header.Template); err != nil {
				log.Printf("Warning: failed to add header for '%s': %v\n", header.Upstream, err)
			}
		}

		// Add role and auth mappings from config file
		for _, role := range yamlConfig.Mappings.Roles {
			for _, r := range role.Roles {
				p.Translator().AddRoleMapping(role.CN, role.Value, []string{r})
			}
		}

		for _, auth := range yamlConfig.Mappings.Auth {
			for _, a := range auth.Auth {
				p.Translator().AddAuthMapping(auth.CN, auth.Value, []string{a})
			}
		}
	}

	// Start proxy
	fmt.Printf("Starting proxy on %s\n", proxyConfig.ListenAddr)
	if err := p.ListenAndServe(proxyConfig); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
