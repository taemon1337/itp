package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/itp/pkg/logger"
	"github.com/itp/pkg/proxy"
	"gopkg.in/yaml.v3"
)

// MappingRule defines a single identity mapping rule
type MappingRule struct {
	Source     string            `yaml:"source" json:"source"`           // "cn", "org", "ou"
	Match      string            `yaml:"match" json:"match"`            // Value to match
	Roles      []string          `yaml:"roles" json:"roles"`            // Roles to add
	Groups     []string          `yaml:"groups" json:"groups"`          // Groups to add
	Auths      []string          `yaml:"auths" json:"auths"`           // Auth values to add
	Attributes map[string]string `yaml:"attributes" json:"attributes"`  // Other attributes to set
}

// HeaderRule defines header injection rules
type HeaderRule struct {
	Upstream string            `yaml:"upstream" json:"upstream"`
	Headers  map[string]string `yaml:"headers" json:"headers"`
}

// Config holds all identity and header configuration
type Config struct {
	Rules   []MappingRule `yaml:"rules" json:"rules"`
	Headers []HeaderRule  `yaml:"headers" json:"headers"`
}

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
	injectHeaders := flag.String("inject-header", "", "Inject headers in format upstream=name=template[,upstream=name=template,...] (e.g. 'backend=X-Viper-User=USER:{{.CommonName}};{{range .Groups}}ROLE:{{.}}{{end}}')")
	injectHeadersUpstream := flag.Bool("inject-headers-upstream", true, "Inject headers into upstream requests")
	injectHeadersDownstream := flag.Bool("inject-headers-downstream", false, "Inject headers into downstream responses")
	addRole := flag.String("add-role", "", "Add roles in format field=value=role1,role2,... (e.g. 'cn=admin=admin,viewer')")
	addAuth := flag.String("add-auth", "", "Add auth values in format field=value=auth1,auth2,... (e.g. 'cn=admin=read,write')")

	// Configuration flags
	configFile := flag.String("config", "", "Path to YAML configuration file for identity mappings and headers")
	routes := flag.String("route", "", "Static routes in format src=dest[,src=dest,...]")
	routeViaDNS := flag.Bool("route-via-dns", false, "Allow routing to unspecified destinations via DNS")

	flag.Parse()

	// Create proxy configuration
	config := &proxy.Config{
		CertFile:           *certFile,
		KeyFile:            *keyFile,
		CAFile:            *caFile,
		ServerName:        *serverName,
		InternalDomain:    *internalDomain,
		ExternalDomain:    *externalDomain,
		AllowUnknownCerts: *allowUnknownClients,
		ListenAddr:        *addr,
		EchoName:         *echoName,
		EchoAddr:         *echoAddr,
		RouteViaDNS:      *routeViaDNS,
		AutoMapCN:        *mapAuto,
		CertStoreType:    *certStoreType,
		ProxyLogger:      logger.New("proxy", logger.LevelInfo),
		RouterLogger:     logger.New("router", logger.LevelInfo),
		TranslatorLogger: logger.New("translator", logger.LevelInfo),
		EchoLogger:      logger.New("echo", logger.LevelInfo),
		InjectHeadersUpstream: *injectHeadersUpstream,
		InjectHeadersDownstream: *injectHeadersDownstream,
	}

	// Create proxy instance
	p, err := proxy.New(config)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Add routes
	if *routes != "" {
		p.AddRoutes(*routes)
	}

	// Add role mappings
	if *addRole != "" {
		parts := strings.SplitN(*addRole, "=", 3)
		if len(parts) != 3 {
			log.Fatalf("Invalid role mapping format: %s", *addRole)
		}
		field, value, roles := parts[0], parts[1], strings.Split(parts[2], ",")
		p.Translator().AddRoleMapping(field, value, roles)
	}

	// Add auth mappings
	if *addAuth != "" {
		parts := strings.SplitN(*addAuth, "=", 3)
		if len(parts) != 3 {
			log.Fatalf("Invalid auth mapping format: %s", *addAuth)
		}
		field, value, auths := parts[0], parts[1], strings.Split(parts[2], ",")
		p.Translator().AddAuthMapping(field, value, auths)
	}

	// Add header injection rules
	if *injectHeaders != "" {
		for _, rule := range strings.Split(*injectHeaders, ",") {
			parts := strings.SplitN(rule, "=", 3)
			if len(parts) != 3 {
				log.Fatalf("Invalid header injection rule format: %s", rule)
			}
			upstream, name, template := parts[0], parts[1], parts[2]
			if err := p.AddHeader(upstream, name, template); err != nil {
				log.Fatalf("Failed to add header injection rule: %v", err)
			}
		}
	}

	// Apply configuration from file or flags
	if *configFile != "" {
		var cfg Config
		data, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			log.Fatalf("Failed to parse config file: %v", err)
		}
		if err := applyConfig(p, &cfg); err != nil {
			log.Fatalf("Failed to apply config: %v", err)
		}
	}

	// Start proxy server
	if err := p.ListenAndServe(config); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
}

func applyConfig(p *proxy.Proxy, cfg *Config) error {
	// Apply identity mappings
	for _, rule := range cfg.Rules {
		// Add roles if specified
		if len(rule.Roles) > 0 {
			p.Translator().AddRoleMapping(rule.Source, rule.Match, rule.Roles)
		}

		// Add groups if specified
		if len(rule.Groups) > 0 {
			p.Translator().AddGroupMapping(rule.Source, rule.Match, rule.Groups)
		}

		// Add auths if specified
		if len(rule.Auths) > 0 {
			p.Translator().AddAuthMapping(rule.Source, rule.Match, rule.Auths)
		}

		// Add attribute mappings if specified
		for k, v := range rule.Attributes {
			p.Translator().AddMapping(rule.Source, k, v)
		}
	}

	// Apply header templates
	for _, rule := range cfg.Headers {
		for headerName, template := range rule.Headers {
			if err := p.AddHeader(rule.Upstream, headerName, template); err != nil {
				return fmt.Errorf("failed to add header template: %v", err)
			}
		}
	}

	return nil
}
