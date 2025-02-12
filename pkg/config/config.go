package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v3"

	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/proxy"
)

// Config represents the complete proxy configuration
type Config struct {
	Server struct {
		Name           string `yaml:"name"`
		ExternalDomain string `yaml:"external_domain"`
		InternalDomain string `yaml:"internal_domain"`
		Listen         string `yaml:"listen"`
		Echo           struct {
			Name string `yaml:"name"`
			Addr string `yaml:"addr"`
		} `yaml:"echo"`
	} `yaml:"server"`

	Certificates struct {
		CertFile string `yaml:"cert_file"`
		KeyFile  string `yaml:"key_file"`
		CAFile   string `yaml:"ca_file"`
		K8sCertManager struct {
			Enabled   bool   `yaml:"enabled"`
			Namespace string `yaml:"namespace"`
			Issuer    struct {
				Name  string `yaml:"name"`
				Kind  string `yaml:"kind"`
				Group string `yaml:"group"`
			} `yaml:"issuer"`
		} `yaml:"k8s_cert_manager"`
	} `yaml:"certificates"`

	Security struct {
		AllowUnknownCerts bool `yaml:"allow_unknown_certs"`
		RouteViaDNS       bool `yaml:"route_via_dns"`
		AutoMapCN         bool `yaml:"auto_map_cn"`
	} `yaml:"security"`

	Routes []struct {
		Source      string `yaml:"source"`
		Destination string `yaml:"destination"`
	} `yaml:"routes"`

	Templates struct {
		Files []struct {
			Name string `yaml:"name"`
			Path string `yaml:"path"`
		} `yaml:"files"`
		Inline []struct {
			Name     string `yaml:"name"`
			Template string `yaml:"template"`
		} `yaml:"inline"`
	} `yaml:"templates"`

	Headers struct {
		InjectUpstream   bool `yaml:"inject_upstream"`
		InjectDownstream bool `yaml:"inject_downstream"`
		Templates []struct {
			Upstream string `yaml:"upstream"`
			Header   string `yaml:"header"`
			Template string `yaml:"template"`
		} `yaml:"templates"`
	} `yaml:"headers"`

	Mappings struct {
		Roles []struct {
			CN    string   `yaml:"cn"`
			Value string   `yaml:"value"`
			Roles []string `yaml:"roles"`
		} `yaml:"roles"`
		Auth []struct {
			CN    string   `yaml:"cn"`
			Value string   `yaml:"value"`
			Auth  []string `yaml:"auth"`
		} `yaml:"auth"`
	} `yaml:"mappings"`
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return &config, nil
}

// validate checks if the configuration is valid
func (c *Config) validate() error {
	// Required fields
	if c.Server.Name == "" {
		return fmt.Errorf("server.name is required")
	}
	if c.Server.ExternalDomain == "" {
		return fmt.Errorf("server.external_domain is required")
	}
	if c.Server.InternalDomain == "" {
		return fmt.Errorf("server.internal_domain is required")
	}

	// Default values
	if c.Server.Listen == "" {
		c.Server.Listen = ":8443"
	}
	if c.Server.Echo.Addr == "" {
		c.Server.Echo.Addr = ":8444"
	}
	if c.Server.Echo.Name == "" {
		c.Server.Echo.Name = fmt.Sprintf("echo.%s", c.Server.InternalDomain)
	}

	// Certificate validation
	if c.Certificates.K8sCertManager.Enabled {
		if c.Certificates.K8sCertManager.Namespace == "" {
			c.Certificates.K8sCertManager.Namespace = "default"
		}
		if c.Certificates.K8sCertManager.Issuer.Name == "" {
			c.Certificates.K8sCertManager.Issuer.Name = "default-issuer"
		}
		if c.Certificates.K8sCertManager.Issuer.Kind == "" {
			c.Certificates.K8sCertManager.Issuer.Kind = "ClusterIssuer"
		}
		if c.Certificates.K8sCertManager.Issuer.Group == "" {
			c.Certificates.K8sCertManager.Issuer.Group = "cert-manager.io"
		}
	} else {
		// If not using k8s cert-manager, validate cert files exist if specified
		if c.Certificates.CertFile != "" {
			if _, err := ioutil.ReadFile(c.Certificates.CertFile); err != nil {
				return fmt.Errorf("failed to read certificate file: %v", err)
			}
		}
		if c.Certificates.KeyFile != "" {
			if _, err := ioutil.ReadFile(c.Certificates.KeyFile); err != nil {
				return fmt.Errorf("failed to read key file: %v", err)
			}
		}
		if c.Certificates.CAFile != "" {
			if _, err := ioutil.ReadFile(c.Certificates.CAFile); err != nil {
				return fmt.Errorf("failed to read CA file: %v", err)
			}
		}
	}

	// Template file validation
	for _, tmpl := range c.Templates.Files {
		if tmpl.Name == "" {
			return fmt.Errorf("template file name is required")
		}
		if tmpl.Path == "" {
			return fmt.Errorf("template file path is required")
		}
		if _, err := ioutil.ReadFile(tmpl.Path); err != nil {
			return fmt.Errorf("failed to read template file %s: %v", tmpl.Path, err)
		}
	}

	// Template inline validation
	for _, tmpl := range c.Templates.Inline {
		if tmpl.Name == "" {
			return fmt.Errorf("inline template name is required")
		}
		if tmpl.Template == "" {
			return fmt.Errorf("inline template content is required")
		}
	}

	return nil
}

// ToProxyConfig converts the YAML configuration to a proxy.Config
func (c *Config) ToProxyConfig() *proxy.Config {
	cfg := proxy.NewProxyConfig(c.Server.Name, c.Server.ExternalDomain, c.Server.InternalDomain)

	// Server settings
	cfg.ListenAddr = c.Server.Listen
	cfg.EchoName = c.Server.Echo.Name
	cfg.EchoAddr = c.Server.Echo.Addr

	// Certificate settings
	if c.Certificates.K8sCertManager.Enabled {
		cfg.UseK8sCertManager = true
		cfg.K8sStoreConfig = &certstore.K8sOptions{
			Namespace:   c.Certificates.K8sCertManager.Namespace,
			IssuerName:  c.Certificates.K8sCertManager.Issuer.Name,
			IssuerKind:  c.Certificates.K8sCertManager.Issuer.Kind,
			IssuerGroup: c.Certificates.K8sCertManager.Issuer.Group,
		}
	} else if c.Certificates.CertFile != "" {
		cfg.WithCertificates(
			c.Certificates.CertFile,
			c.Certificates.KeyFile,
			c.Certificates.CAFile,
		)
	}

	// Security settings
	cfg.AllowUnknownCerts = c.Security.AllowUnknownCerts
	cfg.RouteViaDNS = c.Security.RouteViaDNS
	cfg.AutoMapCN = c.Security.AutoMapCN

	// Header injection settings
	cfg.InjectHeadersUpstream = c.Headers.InjectUpstream
	cfg.InjectHeadersDownstream = c.Headers.InjectDownstream

	return cfg
}
