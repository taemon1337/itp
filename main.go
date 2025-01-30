package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/logger"
	"github.com/itp/pkg/proxy"
)

func main() {
	log.Printf("starting Identity Translation Proxy")

	// TLS configuration flags
	certFile := flag.String("server-cert", "auto", "Server certificate file or 'auto' for auto-generated")
	keyFile := flag.String("server-key", "auto", "Server key file or 'auto' for auto-generated")
	caFile := flag.String("server-ca", "", "CA certificate file for server cert (only used with auto-generated certs)")
	allowUnknownClients := flag.Bool("server-allow-unknown-client-certs", false, "Allow client certificates from unknown CAs")
	mapAuto := flag.Bool("map-auto", false, "Automatically map client CN to upstream CN")
	serverName := flag.String("server-name", "", "If generating server certificates, use this server name for TLS connection")
	internalDomain := flag.String("internal-domain", "cluster.local", "Internal domain for inside/upstream connections (auto generated certs)")
	externalDomain := flag.String("external-domain", "", "External domain for incoming connections, public domain")
	addr := flag.String("addr", ":8443", "address for tls proxy server to listen on")
	certStoreType := flag.String("cert-store", "auto", "Certificate store type (k8s or auto)")
	echoName := flag.String("echo", "", "Name for the echo upstream (e.g. 'echo' to use in --route src=echo)")
	echoAddr := flag.String("echo-addr", ":8444", "Address for echo upstream server")

	// Routing flags
	routes := flag.String("route", "", "Static routes in format src=dest[,src=dest,...]")
	routeViaDNS := flag.Bool("route-via-dns", false, "Allow routing to unspecified destinations by resolving them via DNS (WARNING: enabling this will attempt to resolve unknown hostnames)")

	// Identity mapping flags
	cnMappings := flag.String("map-common-name", "", "Common name mappings in format src=identity[,src=identity,...]")
	orgMappings := flag.String("map-organization", "", "Organization mappings")
	countryMappings := flag.String("map-country", "", "Country mappings")
	stateMappings := flag.String("map-state", "", "State mappings")
	localityMappings := flag.String("map-locality", "", "Locality mappings")
	ouMappings := flag.String("map-organization-unit", "", "Organizational unit mappings")

	// Header injection flags
	injectHeader := flag.String("inject-header", "", "Inject custom headers, format: upstream=header:template[,upstream=header:template,...]")
	injectGroups := flag.String("inject-groups", "", "Inject groups header, format: upstream=header[,upstream=header,...]")
	injectRoles := flag.String("inject-roles", "", "Inject roles header, format: upstream=header[,upstream=header,...]")
	injectCN := flag.String("inject-cn", "", "Inject CN header, format: upstream=header[,upstream=header,...]")
	injectOrg := flag.String("inject-org", "", "Inject organization header, format: upstream=header[,upstream=header,...]")
	injectOU := flag.String("inject-ou", "", "Inject organizational unit header, format: upstream=header[,upstream=header,...]")

	// Conditional role mapping flags
	rolesToCN := flag.String("add-role-to-cn", "", "Add roles when CN matches, format: cn=role1,role2[;cn=role1,role2,...]")
	rolesToOrg := flag.String("add-role-to-org", "", "Add roles when Organization matches, format: org=role1,role2[;org=role1,role2,...]")
	rolesToOU := flag.String("add-role-to-ou", "", "Add roles when OU matches, format: ou=role1,role2[;ou=role1,role2,...]")

	// Conditional group mapping flags
	groupsToCN := flag.String("add-group-to-cn", "", "Add groups when CN matches, format: cn=group1,group2[;cn=group1,group2,...]")
	groupsToOrg := flag.String("add-group-to-org", "", "Add groups when Organization matches, format: org=group1,group2[;org=group1,group2,...]")
	groupsToOU := flag.String("add-group-to-ou", "", "Add groups when OU matches, format: ou=group1,group2[;ou=group1,group2,...]")

	// Logging flags
	proxyLogLevel := flag.String("proxy-log-level", "INFO", "Log level for proxy component (ERROR, WARN, INFO, DEBUG)")
	routerLogLevel := flag.String("router-log-level", "DEBUG", "Log level for router component (ERROR, WARN, INFO, DEBUG)")
	translatorLogLevel := flag.String("translator-log-level", "INFO", "Log level for translator component (ERROR, WARN, INFO, DEBUG)")
	echoLogLevel := flag.String("echo-log-level", "INFO", "Log level for echo server component (ERROR, WARN, INFO, DEBUG)")

	flag.Parse()

	// Initialize loggers
	proxyLogger, err := logger.ParseLevel(*proxyLogLevel)
	if err != nil {
		log.Fatalf("Invalid proxy log level: %v", err)
	}
	routerLogger, err := logger.ParseLevel(*routerLogLevel)
	if err != nil {
		log.Fatalf("Invalid router log level: %v", err)
	}
	translatorLogger, err := logger.ParseLevel(*translatorLogLevel)
	if err != nil {
		log.Fatalf("Invalid translator log level: %v", err)
	}
	echoLogger, err := logger.ParseLevel(*echoLogLevel)
	if err != nil {
		log.Fatalf("Invalid echo log level: %v", err)
	}

	// Create proxy configuration
	config := &proxy.Config{
		// Server TLS config
		CertFile:          *certFile,
		KeyFile:           *keyFile,
		CAFile:           *caFile,
		ServerName:       *serverName,
		InternalDomain:   *internalDomain,
		ExternalDomain:   *externalDomain,
		AllowUnknownCerts: *allowUnknownClients,
		ListenAddr:        *addr,

		// Echo server config
		EchoName:         *echoName,
		EchoAddr:         *echoAddr,
		RouteViaDNS:      *routeViaDNS,
		AutoMapCN:        *mapAuto,

		// Certificate store config
		CertStoreType:    *certStoreType,
		CertStoreTTL:     24 * time.Hour,
		CertStoreCacheDuration: time.Hour,
		CertStoreNamespace: "default", // TODO: Add namespace flag if needed

		// Logger config
		ProxyLogger:      logger.New("proxy", proxyLogger),
		RouterLogger:     logger.New("router", routerLogger),
		TranslatorLogger: logger.New("translator", translatorLogger),
		EchoLogger:      logger.New("echo", echoLogger),
	}

	// Initialize proxy
	p, err := proxy.New(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Add static routes
	if *routes != "" {
		p.AddRoutes(*routes)
	}

	// Add identity mappings
	if *cnMappings != "" {
		addMappings(p.Translator(), "cn", *cnMappings)
	}
	if *orgMappings != "" {
		addMappings(p.Translator(), "o", *orgMappings)
	}
	if *countryMappings != "" {
		addMappings(p.Translator(), "c", *countryMappings)
	}
	if *stateMappings != "" {
		addMappings(p.Translator(), "st", *stateMappings)
	}
	if *localityMappings != "" {
		addMappings(p.Translator(), "l", *localityMappings)
	}
	if *ouMappings != "" {
		addMappings(p.Translator(), "ou", *ouMappings)
	}

	// Add role mappings
	if *rolesToCN != "" {
		addRoleMappings(p.Translator(), "cn", *rolesToCN)
	}
	if *rolesToOrg != "" {
		addRoleMappings(p.Translator(), "o", *rolesToOrg)
	}
	if *rolesToOU != "" {
		addRoleMappings(p.Translator(), "ou", *rolesToOU)
	}

	// Add group mappings
	if *groupsToCN != "" {
		addGroupMappings(p.Translator(), "cn", *groupsToCN)
	}
	if *groupsToOrg != "" {
		addGroupMappings(p.Translator(), "o", *groupsToOrg)
	}
	if *groupsToOU != "" {
		addGroupMappings(p.Translator(), "ou", *groupsToOU)
	}

	// Add header templates
	if *injectHeader != "" {
		addCustomHeaders(p, *injectHeader)
	}
	if *injectGroups != "" {
		addCommonHeaders(p, "groups", *injectGroups)
	}
	if *injectRoles != "" {
		addCommonHeaders(p, "roles", *injectRoles)
	}
	if *injectCN != "" {
		addCommonHeaders(p, "cn", *injectCN)
	}
	if *injectOrg != "" {
		addCommonHeaders(p, "org", *injectOrg)
	}
	if *injectOU != "" {
		addCommonHeaders(p, "ou", *injectOU)
	}

	// Start proxy server
	log.Fatal(p.ListenAndServe(config))
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
		roles := strings.Split(parts[1], ",")
		t.AddRoleMapping(field, parts[0], roles)
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
		groups := strings.Split(parts[1], ",")
		t.AddGroupMapping(field, parts[0], groups)
	}
}

// addCustomHeaders adds custom header templates from a comma-separated string
func addCustomHeaders(p *proxy.Proxy, mappings string) {
	for _, mapping := range strings.Split(mappings, ",") {
		parts := strings.Split(mapping, "=")
		if len(parts) != 2 {
			log.Printf("Invalid header format: %s", mapping)
			continue
		}

		headerParts := strings.Split(parts[1], ":")
		if len(headerParts) != 2 {
			log.Printf("Invalid header value format: %s", parts[1])
			continue
		}

		if err := p.AddHeader(parts[0], headerParts[0], headerParts[1]); err != nil {
			log.Printf("Failed to add header template: %v", err)
		}
	}
}

// addCommonHeaders adds common header mappings from a comma-separated string
func addCommonHeaders(p *proxy.Proxy, headerType string, mappings string) {
	for _, mapping := range strings.Split(mappings, ",") {
		parts := strings.Split(mapping, "=")
		if len(parts) != 2 {
			log.Printf("Invalid header format: %s", mapping)
			continue
		}

		if err := p.AddCommonHeader(headerType, parts[0], parts[1]); err != nil {
			log.Printf("Failed to add common header: %v", err)
		}
	}
}
