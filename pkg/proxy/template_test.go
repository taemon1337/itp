package proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/itp/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestTemplateManager(t *testing.T) {
	logger := logger.New("template", logger.LevelInfo)
	tm := NewTemplateManager(logger)

	t.Run("add and get template string", func(t *testing.T) {
		// Add a template
		err := tm.AddTemplateString("user", "User:{{.CommonName}}")
		assert.NoError(t, err)

		// Get the template
		tmpl, err := tm.GetTemplate("user")
		assert.NoError(t, err)
		assert.NotNil(t, tmpl)

		// Try to get non-existent template
		tmpl, err = tm.GetTemplate("nonexistent")
		assert.Error(t, err)
		assert.Nil(t, tmpl)
	})

	t.Run("add and get template file", func(t *testing.T) {
		// Create a temporary template file
		dir := t.TempDir()
		templatePath := filepath.Join(dir, "test.tmpl")
		err := os.WriteFile(templatePath, []byte("User:{{.CommonName}}"), 0644)
		assert.NoError(t, err)

		// Add template from file
		err = tm.AddTemplateFile("user-file", templatePath)
		assert.NoError(t, err)

		// Get the template
		tmpl, err := tm.GetTemplate("user-file")
		assert.NoError(t, err)
		assert.NotNil(t, tmpl)

		// Try to add from non-existent file
		err = tm.AddTemplateFile("bad-file", "nonexistent.tmpl")
		assert.Error(t, err)
	})

	t.Run("add invalid template", func(t *testing.T) {
		// Try to add invalid template
		err := tm.AddTemplateString("invalid", "{{.Invalid}")
		assert.Error(t, err)
	})

	t.Run("add duplicate template", func(t *testing.T) {
		// Add first template
		err := tm.AddTemplateString("duplicate", "User:{{.CommonName}}")
		assert.NoError(t, err)

		// Try to add duplicate template
		err = tm.AddTemplateString("duplicate", "Different:{{.CommonName}}")
		assert.Error(t, err)
	})
}
