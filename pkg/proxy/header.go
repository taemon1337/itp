package proxy

import (
	"bytes"
	"fmt"
	"log"
	"text/template"

	"github.com/itp/pkg/identity"
)

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
	mappings map[string][]HeaderTemplate
	templates map[string]map[string]*template.Template
}

// NewHeaderInjector creates a new header injector
func NewHeaderInjector() *HeaderInjector {
	return &HeaderInjector{
		mappings: make(map[string][]HeaderTemplate),
		templates: make(map[string]map[string]*template.Template),
	}
}

// AddHeader adds a header template for an upstream
func (h *HeaderInjector) AddHeader(upstream string, headerName string, templateStr string) error {
	log.Printf("Adding header template for upstream %q: %s = %q", upstream, headerName, templateStr)
	
	// Parse template
	tmpl, err := template.New("header").Parse(templateStr)
	if err != nil {
		log.Printf("Failed to parse template: %v", err)
		return fmt.Errorf("failed to parse template: %v", err)
	}

	// Test template with empty identity to catch invalid fields
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, &identity.Identity{}); err != nil {
		log.Printf("Invalid template: %v", err)
		return fmt.Errorf("invalid template: %v", err)
	}

	// Store template
	if h.templates[upstream] == nil {
		h.templates[upstream] = make(map[string]*template.Template)
	}
	h.templates[upstream][headerName] = tmpl
	log.Printf("Successfully added header template for %q", headerName)

	return nil
}

// AddCommonHeader adds a common header (groups, roles, etc) for an upstream
func (h *HeaderInjector) AddCommonHeader(headerType, upstream, headerName string) error {
	log.Printf("Adding common header of type %q for upstream %q: %s", headerType, upstream, headerName)
	
	var template string
	switch headerType {
	case "groups":
		template = "{{ range .Groups }}{{ . }}{{ end }}"
	case "roles":
		template = "{{ range .Roles }}{{ . }}{{ end }}"
	case "cn":
		template = "{{ .CommonName }}"
	case "org":
		template = "{{ range .Organization }}{{ . }}{{ end }}"
	case "ou":
		template = "{{ range .OrganizationUnit }}{{ . }}{{ end }}"
	default:
		log.Printf("Unknown header type: %s", headerType)
		return fmt.Errorf("unknown header type: %s", headerType)
	}
	
	log.Printf("Using template: %q", template)
	return h.AddHeader(upstream, headerName, template)
}

// GetHeaders returns the headers that should be injected for an upstream
func (h *HeaderInjector) GetHeaders(upstream string, identities []*identity.Identity) map[string]string {
	log.Printf("Getting headers for upstream %q with %d identities", upstream, len(identities))
	
	if len(identities) == 0 {
		log.Printf("No identities provided, skipping header injection")
		return map[string]string{}
	}

	// Get templates for this upstream
	templates, ok := h.templates[upstream]
	if !ok {
		log.Printf("No header templates found for upstream %q", upstream)
		return map[string]string{}
	}

	log.Printf("Found %d header templates for upstream %q", len(templates), upstream)
	log.Printf("First identity: %+v", identities[0])

	// Execute templates with first identity
	headers := make(map[string]string)
	for name, tmpl := range templates {
		log.Printf("Executing template for header %q: %v", name, tmpl.Name())
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, identities[0]); err != nil {
			log.Printf("Failed to execute template for header %s: %v", name, err)
			continue
		}
		value := buf.String()
		if value != "" && value != "[]" {
			log.Printf("Setting header %q = %q", name, value)
			headers[name] = value
		} else {
			log.Printf("Skipping empty or null header %q (value=%q)", name, value)
		}
	}

	return headers
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
