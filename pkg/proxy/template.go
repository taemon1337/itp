package proxy

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/itp/pkg/logger"
)

// TemplateManager manages named templates that can be referenced in header injection
type TemplateManager struct {
	templates map[string]*template.Template
	logger    *logger.Logger
}

// NewTemplateManager creates a new template manager
func NewTemplateManager(logger *logger.Logger) *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*template.Template),
		logger:    logger,
	}
}

// WrapTemplateReference ensures all template references include the context
func (tm *TemplateManager) WrapTemplateReference(templateStr string) string {
    // Find all template references using regex
    re := regexp.MustCompile(`{{template "([^"]+)"([^}]*)}}`)
    
    // Replace each template reference that doesn't have a context
    return re.ReplaceAllStringFunc(templateStr, func(match string) string {
        if strings.Contains(match, " .") {
            // Already has context
            return match
        }
        // Add context
        return strings.TrimSuffix(match, "}}") + " .}}"
    })
}

// CreateTemplateReference creates a template reference with context
func (tm *TemplateManager) CreateTemplateReference(name string) string {
    return fmt.Sprintf(`{{template "%s" .}}`, name)
}

// AddTemplateString adds a new template from a string
func (tm *TemplateManager) AddTemplateString(name, templateStr string) error {
	// Ensure all template references include context
	templateStr = tm.WrapTemplateReference(templateStr)

	// Create a new template with the common functions
	tmpl := template.New(name).Funcs(template.FuncMap{
		"join":  strings.Join,
		"comma": func(items []string) string { return strings.Join(items, ",") },
		"space": func(items []string) string { return strings.Join(items, " ") },
	})

	// Add all existing templates to this template
	for tname, t := range tm.templates {
		if _, err := tmpl.AddParseTree(tname, t.Tree); err != nil {
			return fmt.Errorf("failed to add template %q to %q: %v", tname, name, err)
		}
	}

	// Parse the new template
	tmpl, err := tmpl.Parse(templateStr)
	if err != nil {
		return fmt.Errorf("failed to parse template %q: %v", name, err)
	}

	// Add the new template to all existing templates
	for _, t := range tm.templates {
		if _, err := t.AddParseTree(name, tmpl.Tree); err != nil {
			return fmt.Errorf("failed to add template %q to existing templates: %v", name, err)
		}
	}

	tm.templates[name] = tmpl
	tm.logger.Info("Added template %q: %s", name, templateStr)
	return nil
}

// AddTemplateFile adds a new template from a file
func (tm *TemplateManager) AddTemplateFile(name, filepath string) error {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read template file %q: %v", filepath, err)
	}

	return tm.AddTemplateString(name, string(content))
}

// GetTemplate retrieves a template by name
func (tm *TemplateManager) GetTemplate(name string) (*template.Template, error) {
	tmpl, ok := tm.templates[name]
	if !ok {
		return nil, fmt.Errorf("template %q not found", name)
	}
	return tmpl, nil
}

// ExecuteTemplate executes a named template with the given data
func (tm *TemplateManager) ExecuteTemplate(name string, data interface{}) (string, error) {
	tmpl, err := tm.GetTemplate(name)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %q: %v", name, err)
	}

	return buf.String(), nil
}
