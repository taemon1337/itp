package proxy

import (
	"bytes"
	"fmt"
	"log"
	"text/template"

	"github.com/itp/pkg/identity"
)

// RoleConfig represents a custom role configuration
type RoleConfig struct {
	Name     string            // Name of the role (e.g., "admin", "developer")
	Template string            // Template for the role value
	Mappings map[string]string // Custom mappings for role values
}

// HeaderTemplate represents a template for injecting headers
type HeaderTemplate struct {
	Name     string
	Template string
	Type     string
}

// HeaderMapping maps an upstream to its header templates
type HeaderMapping struct {
	Upstream string
	Headers  []HeaderTemplate
}

// HeaderInjector manages header injection for upstreams
type HeaderInjector struct {
	mappings   map[string][]HeaderTemplate
	templates  map[string]map[string]*template.Template
	roleConfig map[string]*RoleConfig // Maps role name to its configuration
	logger     *log.Logger
}

// NewHeaderInjector creates a new header injector
func NewHeaderInjector() *HeaderInjector {
	return &HeaderInjector{
		mappings:   make(map[string][]HeaderTemplate),
		templates:  make(map[string]map[string]*template.Template),
		roleConfig: make(map[string]*RoleConfig),
		logger:     log.Default(),
	}
}

// AddCustomRole adds a custom role configuration
func (h *HeaderInjector) AddCustomRole(name, templateStr string) error {
	h.logger.Printf("Adding custom role %q with template %q", name, templateStr)
	
	// Parse template to validate it
	tmpl := template.New("role")
	_, err := tmpl.Parse(templateStr)
	if err != nil {
		h.logger.Printf("Failed to parse role template: %v", err)
		return fmt.Errorf("failed to parse role template: %v", err)
	}

	h.roleConfig[name] = &RoleConfig{
		Name:     name,
		Template: templateStr,
		Mappings: make(map[string]string),
	}
	return nil
}

// AddRoleMapping adds a mapping for a custom role
func (h *HeaderInjector) AddRoleMapping(roleName, key, value string) error {
	role, ok := h.roleConfig[roleName]
	if !ok {
		return fmt.Errorf("unknown role name: %s", roleName)
	}

	h.logger.Printf("Adding role mapping %s=%s for role %q", key, value, roleName)
	role.Mappings[key] = value
	return nil
}

// AddHeader adds a header template for an upstream
func (h *HeaderInjector) AddHeader(upstream string, headerName string, templateStr string) error {
	h.logger.Printf("Adding header template for upstream %q: %s = %q", upstream, headerName, templateStr)
	
	// Parse template
	tmpl, err := template.New("header").Parse(templateStr)
	if err != nil {
		h.logger.Printf("Failed to parse template: %v", err)
		return fmt.Errorf("failed to parse template: %v", err)
	}

	// Validate template with test identity that has non-empty slices
	testIdentity := &identity.Identity{
		CommonName:       "test",
		Organization:     []string{"test-org"},
		OrganizationUnit: []string{"test-ou"},
		Locality:        []string{"test-locality"},
		Country:         []string{"test-country"},
		State:           []string{"test-state"},
		Groups:          []string{"test-group"},
		Roles:           []string{"test-role"},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, testIdentity); err != nil {
		h.logger.Printf("Invalid template: %v", err)
		return fmt.Errorf("invalid template: %v", err)
	}

	// Initialize upstream templates map if needed
	if _, ok := h.templates[upstream]; !ok {
		h.templates[upstream] = make(map[string]*template.Template)
	}
	h.templates[upstream][headerName] = tmpl
	h.logger.Printf("Successfully added header template for %q", headerName)

	return nil
}

// AddCommonHeader adds a common header (groups, roles, etc) for an upstream
func (h *HeaderInjector) AddCommonHeader(headerType, upstream, headerName string) error {
	h.logger.Printf("Adding common header of type %q for upstream %q: %s", headerType, upstream, headerName)
	
	var templateStr string
	switch headerType {
	case "groups":
		templateStr = "{{ range .Groups }}{{ . }}{{ end }}"
	case "roles":
		// Check if this is a custom role
		if role, ok := h.roleConfig[headerName]; ok {
			templateStr = role.Template
		} else {
			templateStr = "{{ range .Roles }}{{ . }}{{ end }}"
		}
	case "cn":
		templateStr = "{{ .CommonName }}"
	case "org":
		templateStr = "{{ range .Organization }}{{ . }}{{ end }}"
	case "ou":
		templateStr = "{{ range .OrganizationUnit }}{{ . }}{{ end }}"
	default:
		h.logger.Printf("Unknown header type: %s", headerType)
		return fmt.Errorf("unknown header type: %s", headerType)
	}
	
	h.logger.Printf("Using template: %q", templateStr)
	return h.AddHeader(upstream, headerName, templateStr)
}

func (h *HeaderInjector) HasHeaders(upstream string, identity *identity.Identity) bool {
	_, ok := h.templates[upstream]
	return ok
}

// GetHeaders returns the headers that should be injected for an upstream
func (h *HeaderInjector) GetHeaders(upstream string, identity *identity.Identity) (map[string]string, error) {
	h.logger.Printf("Getting headers for upstream %q with identity %+v", upstream, identity)

	// Get templates for this upstream
	templates, ok := h.templates[upstream]
	if !ok {
		h.logger.Printf("No header templates found for upstream %q", upstream)
		return nil, nil
	}

	h.logger.Printf("Found %d header templates for upstream %q", len(templates), upstream)

	headers := make(map[string]string)
	for header, tmpl := range templates {
		h.logger.Printf("Executing template for header %q: %s", header, tmpl.Name())
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, identity); err != nil {
			h.logger.Printf("Failed to execute template for header %q: %v", header, err)
			continue
		}
		value := buf.String()
		h.logger.Printf("Setting header %q = %q", header, value)
		headers[header] = value
	}

	return headers, nil
}

// appendUnique appends strings that haven't been seen before
func appendUnique(slice []string, items []string, seen map[string]bool) []string {
	if seen == nil {
		seen = make(map[string]bool)
	}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			slice = append(slice, item)
		}
	}
	return slice
}
