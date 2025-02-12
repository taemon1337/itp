package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create a test template file
	templatePath := filepath.Join(tmpDir, "user.tmpl")
	err := os.WriteFile(templatePath, []byte("User:{{.CommonName}}"), 0644)
	assert.NoError(t, err)

	// Create test certificate files
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	caPath := filepath.Join(tmpDir, "ca.pem")
	for _, path := range []string{certPath, keyPath, caPath} {
		err := os.WriteFile(path, []byte("test"), 0644)
		assert.NoError(t, err)
	}

	// Create test config file
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := []byte(`
server:
  name: proxy.example.com
  external_domain: external.com
  internal_domain: cluster.local
  listen: :8443
  echo:
    name: echo.cluster.local
    addr: :8444

certificates:
  cert_file: ` + certPath + `
  key_file: ` + keyPath + `
  ca_file: ` + caPath + `
  k8s_cert_manager:
    enabled: false

security:
  allow_unknown_certs: false
  route_via_dns: true
  auto_map_cn: true

routes:
  - source: app.external.com
    destination: app.cluster.local
  - source: api.external.com
    destination: api.cluster.local:8080

templates:
  files:
    - name: user-info
      path: ` + templatePath + `
  inline:
    - name: role-info
      template: "Role:{{.Role}}"

headers:
  inject_upstream: true
  inject_downstream: false
  templates:
    - upstream: app.cluster.local
      header: X-User-Info
      template: "{{template \"user-info\"}}"

mappings:
  roles:
    - cn: admin
      value: admin-user
      roles: [admin, superuser]
  auth:
    - cn: "*"
      value: "*"
      auth: [read, write]
`)
	err = os.WriteFile(configPath, configContent, 0644)
	assert.NoError(t, err)

	// Test loading valid config
	config, err := LoadFromFile(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, config)

	// Verify config values
	assert.Equal(t, "proxy.example.com", config.Server.Name)
	assert.Equal(t, "external.com", config.Server.ExternalDomain)
	assert.Equal(t, "cluster.local", config.Server.InternalDomain)
	assert.Equal(t, ":8443", config.Server.Listen)
	assert.Equal(t, "echo.cluster.local", config.Server.Echo.Name)
	assert.Equal(t, ":8444", config.Server.Echo.Addr)

	assert.Equal(t, certPath, config.Certificates.CertFile)
	assert.Equal(t, keyPath, config.Certificates.KeyFile)
	assert.Equal(t, caPath, config.Certificates.CAFile)
	assert.False(t, config.Certificates.K8sCertManager.Enabled)

	assert.False(t, config.Security.AllowUnknownCerts)
	assert.True(t, config.Security.RouteViaDNS)
	assert.True(t, config.Security.AutoMapCN)

	assert.Len(t, config.Routes, 2)
	assert.Equal(t, "app.external.com", config.Routes[0].Source)
	assert.Equal(t, "app.cluster.local", config.Routes[0].Destination)

	assert.Len(t, config.Templates.Files, 1)
	assert.Equal(t, "user-info", config.Templates.Files[0].Name)
	assert.Equal(t, templatePath, config.Templates.Files[0].Path)

	assert.Len(t, config.Templates.Inline, 1)
	assert.Equal(t, "role-info", config.Templates.Inline[0].Name)
	assert.Equal(t, "Role:{{.Role}}", config.Templates.Inline[0].Template)

	assert.True(t, config.Headers.InjectUpstream)
	assert.False(t, config.Headers.InjectDownstream)

	assert.Len(t, config.Mappings.Roles, 1)
	assert.Equal(t, "admin", config.Mappings.Roles[0].CN)
	assert.Equal(t, "admin-user", config.Mappings.Roles[0].Value)
	assert.Equal(t, []string{"admin", "superuser"}, config.Mappings.Roles[0].Roles)

	// Convert to proxy config
	proxyConfig := config.ToProxyConfig()
	assert.NotNil(t, proxyConfig)
	assert.Equal(t, "proxy.example.com", proxyConfig.ServerName)
	assert.Equal(t, "external.com", proxyConfig.ExternalDomain)
	assert.Equal(t, "cluster.local", proxyConfig.InternalDomain)
	assert.Equal(t, ":8443", proxyConfig.ListenAddr)
	assert.Equal(t, certPath, proxyConfig.CertFile)
	assert.Equal(t, keyPath, proxyConfig.KeyFile)
	assert.Equal(t, caPath, proxyConfig.CAFile)
	assert.False(t, proxyConfig.UseK8sCertManager)
	assert.True(t, proxyConfig.RouteViaDNS)
	assert.True(t, proxyConfig.AutoMapCN)
}

func TestLoadFromFileErrors(t *testing.T) {
	// Test loading non-existent file
	_, err := LoadFromFile("nonexistent.yaml")
	assert.Error(t, err)

	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Test invalid YAML
	err = os.WriteFile(configPath, []byte("invalid: yaml: content"), 0644)
	assert.NoError(t, err)
	_, err = LoadFromFile(configPath)
	assert.Error(t, err)

	// Test missing required fields
	err = os.WriteFile(configPath, []byte("server: {}"), 0644)
	assert.NoError(t, err)
	_, err = LoadFromFile(configPath)
	assert.Error(t, err)
}
