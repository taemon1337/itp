package proxy

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/logger"
)

// HeaderInjector manages header injection for upstreams
type HeaderInjector struct {
	headers   map[string]map[string]*template.Template
	templates *TemplateManager
	logger    *logger.Logger
}

// NewHeaderInjector creates a new header injector
func NewHeaderInjector(logger *logger.Logger) *HeaderInjector {
	return &HeaderInjector{
		headers:   make(map[string]map[string]*template.Template),
		templates: NewTemplateManager(logger),
		logger:    logger,
	}
}



// AddHeader adds a header template for an upstream
func (h *HeaderInjector) AddHeader(upstream string, headerName string, templateStr string) error {
    h.logger.Info("Adding header template for upstream %q: %s = %q", upstream, headerName, templateStr)
    
    // Ensure template references include context
    templateStr = h.templates.WrapTemplateReference(templateStr)

    // Check if the template string references a named template
    if strings.HasPrefix(templateStr, "{{template \"") && strings.HasSuffix(templateStr, "\"}}") {
        // Extract template name
        name := strings.TrimPrefix(strings.TrimSuffix(templateStr, "\"}}"), "{{template \"")
        
        // Verify template exists
        if _, err := h.templates.GetTemplate(name); err != nil {
            return fmt.Errorf("referenced template %q not found: %v", name, err)
        }
    }

    // Create template with custom functions and template references
    tmpl := template.New("header").Funcs(template.FuncMap{
        "join":  strings.Join,
        "comma": func(items []string) string { return strings.Join(items, ",") },
        "space": func(items []string) string { return strings.Join(items, " ") },
    })

    // Add all named templates as sub-templates
    for name, t := range h.templates.templates {
        if _, err := tmpl.AddParseTree(name, t.Tree); err != nil {
            return fmt.Errorf("failed to add template %q: %v", name, err)
        }
    }

    // Parse the header template
    tmpl, err := tmpl.Parse(templateStr)
    if err != nil {
        h.logger.Error("Failed to parse template: %v", err)
        return fmt.Errorf("failed to parse template: %v", err)
    }

    // Validate template with test identity
    testIdentity := &identity.Identity{
        CommonName:       "test",
        Organization:     []string{"test-org"},
        OrganizationUnit: []string{"test-ou"},
        Locality:         []string{"test-locality"},
		Country:          []string{"test-country"},
		State:            []string{"test-state"},
		Groups:           []string{"test-group"},
		Roles:            []string{"test-role"},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, testIdentity); err != nil {
		h.logger.Error("Invalid template: %v", err)
		return fmt.Errorf("invalid template: %v", err)
	}

	// Initialize upstream templates map if needed
	if _, ok := h.headers[upstream]; !ok {
		h.headers[upstream] = make(map[string]*template.Template)
	}
	h.headers[upstream][headerName] = tmpl
	h.logger.Info("Successfully added header template for %q", headerName)

	return nil
}

// AddCommonHeader adds a common header (groups, roles, etc) for an upstream
func (h *HeaderInjector) AddCommonHeader(headerType, upstream, headerName string) error {
	h.logger.Info("Adding common header of type %q for upstream %q: %s", headerType, upstream, headerName)

	var templateStr string
	switch headerType {
	case "groups":
		templateStr = "{{.Groups | join \"; \"}}"
	case "roles":
		templateStr = "{{.Roles | join \"; \"}}"
	case "cn":
		templateStr = "{{.CommonName}}"
	case "org":
		templateStr = "{{.Organization | join \"; \"}}"
	case "ou":
		templateStr = "{{.OrganizationUnit | join \"; \"}}"
	default:
		h.logger.Error("Unknown header type: %s", headerType)
		return fmt.Errorf("unknown header type: %s", headerType)
	}

	h.logger.Debug("Using template: %q", templateStr)
	return h.AddHeader(upstream, headerName, templateStr)
}

func (h *HeaderInjector) HasHeaders(upstream string, identity *identity.Identity) bool {
	_, ok := h.headers[upstream]
	return ok
}

// AddHeaderTemplate adds a header that uses a named template
func (h *HeaderInjector) AddHeaderTemplate(upstream, headerName, templateName string) error {
	h.logger.Info("Adding header template for upstream %q: %s = template %q", upstream, headerName, templateName)

	// Verify template exists
	if _, err := h.templates.GetTemplate(templateName); err != nil {
		return fmt.Errorf("template %q not found: %v", templateName, err)
	}

	// Create the template reference
	templateStr := fmt.Sprintf("{{template \"%s\"}}", templateName)
	return h.AddHeader(upstream, headerName, templateStr)
}

// GetHeaders returns the headers that should be injected for an upstream
func (h *HeaderInjector) GetHeaders(upstream string, identity *identity.Identity) (map[string]string, error) {
	h.logger.Debug("Getting headers for upstream %q with identity %+v", upstream, identity)
	h.logger.Debug("Identity fields: CommonName=%q, Organization=%v, Groups=%v, Roles=%v", 
		identity.CommonName, identity.Organization, identity.Groups, identity.Roles)

	// Get templates for this upstream
	templates, ok := h.headers[upstream]
	if !ok {
		h.logger.Debug("No header templates found for upstream %q", upstream)
		return nil, nil
	}

	h.logger.Debug("Found %d header templates for upstream %q", len(templates), upstream)

	headers := make(map[string]string)
	for header, tmpl := range templates {
		h.logger.Debug("Executing template for header %q: %s", header, tmpl.Name())
		h.logger.Debug("Template content: %s", tmpl.Tree.Root.String())
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, identity); err != nil {
			h.logger.Error("Failed to execute template for header %q: %v", header, err)
			continue
		}
		value := buf.String()
		h.logger.Debug("Setting header %q = %q", header, value)
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
