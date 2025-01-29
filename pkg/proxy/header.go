package proxy

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/itp/pkg/identity"
)

// HeaderTemplate represents a template for injecting headers
type HeaderTemplate struct {
	Name     string
	Template string
}

// HeaderMapping maps an upstream to its header templates
type HeaderMapping struct {
	Upstream string
	Headers  []HeaderTemplate
}

// HeaderInjector manages header injection for upstreams
type HeaderInjector struct {
	mappings map[string][]HeaderTemplate
}

// NewHeaderInjector creates a new header injector
func NewHeaderInjector() *HeaderInjector {
	return &HeaderInjector{
		mappings: make(map[string][]HeaderTemplate),
	}
}

// AddHeader adds a header template for an upstream
func (h *HeaderInjector) AddHeader(upstream, headerName, templateStr string) error {
	// Validate template
	tmpl, err := template.New("header").Parse(templateStr)
	if err != nil {
		return fmt.Errorf("invalid template %q: %v", templateStr, err)
	}

	// Test template with empty data to catch basic syntax errors
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, identity.Identity{}); err != nil {
		return fmt.Errorf("template error: %v", err)
	}

	h.mappings[upstream] = append(h.mappings[upstream], HeaderTemplate{
		Name:     headerName,
		Template: templateStr,
	})
	return nil
}

// AddCommonHeader adds a common header (groups, roles, etc) for an upstream
func (h *HeaderInjector) AddCommonHeader(headerType, upstream, headerName string) error {
	var template string
	switch headerType {
	case "groups":
		template = "{{.Groups}}"
	case "roles":
		template = "{{.Roles}}"
	case "cn":
		template = "{{.CommonName}}"
	case "org":
		template = "{{.Organization}}"
	case "ou":
		template = "{{.OrganizationUnit}}" // Fix OrganizationalUnit to OrganizationUnit in template
	default:
		return fmt.Errorf("unknown header type: %s", headerType)
	}
	return h.AddHeader(upstream, headerName, template)
}

// GetHeaders returns all headers that should be injected for an upstream
func (h *HeaderInjector) GetHeaders(upstream string, identities []identity.Identity) map[string]string {
	headers := make(map[string]string)
	templates, ok := h.mappings[upstream]
	if !ok {
		return headers
	}

	// Prepare template data combining all identities
	data := struct {
		CommonName         string
		Organization      []string
		OrganizationUnit []string
		Groups           []string
		Roles            []string
		Country          []string
		State            []string
		Locality         []string
		// Add single identity for backwards compatibility
		Identity *identity.Identity
	}{
		Identity: &identities[0], // First identity for backwards compatibility
	}

	// Combine data from all identities
	seen := make(map[string]bool)
	for _, id := range identities {
		if id.CommonName != "" {
			data.CommonName = id.CommonName
		}
		data.Organization = appendUnique(data.Organization, id.Organization, seen)
		data.OrganizationUnit = appendUnique(data.OrganizationUnit, id.OrganizationUnit, seen)
		data.Country = appendUnique(data.Country, id.Country, seen)
		data.State = appendUnique(data.State, id.State, seen)
		data.Locality = appendUnique(data.Locality, id.Locality, seen)
		
		// Add any additional groups and roles from mappings
		// These will be added by the translator
		data.Groups = appendUnique(data.Groups, []string{}, seen)
		data.Roles = appendUnique(data.Roles, []string{}, seen)
	}

	// Execute each template
	for _, tmpl := range templates {
		t, err := template.New("header").Parse(tmpl.Template)
		if err != nil {
			continue // Skip invalid templates
		}

		var buf bytes.Buffer
		if err := t.Execute(&buf, data); err != nil {
			continue // Skip failed templates
		}

		headers[tmpl.Name] = buf.String()
	}

	return headers
}

// appendUnique appends strings that haven't been seen before
func appendUnique(slice []string, items []string, seen map[string]bool) []string {
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			slice = append(slice, item)
		}
	}
	return slice
}
