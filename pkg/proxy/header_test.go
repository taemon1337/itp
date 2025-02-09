package proxy

import (
	"reflect"
	"testing"

	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestHeaderInjector(t *testing.T) {
	logger := logger.New("header", logger.LevelInfo)
	h := NewHeaderInjector(logger)

	// Test identity for all tests
	ident := &identity.Identity{
		CommonName:       "test-user",
		Organization:     []string{"org1", "org2"},
		OrganizationUnit: []string{"unit1", "unit2"},
		Locality:         []string{"loc1", "loc2"},
		Country:          []string{"US", "CA"},
		State:            []string{"CA", "NY"},
		Groups:           []string{"group1", "group2"},
		Roles:            []string{"role1", "role2"},
		Auths:            []string{"auth1", "auth2"},
	}

	t.Run("basic header template", func(t *testing.T) {
		// Test adding header template
		err := h.AddHeader("echo.example.com", "X-User", "{{.CommonName}}")
		assert.NoError(t, err)

		// Test getting headers
		headers, err := h.GetHeaders("echo.example.com", ident)
		assert.NoError(t, err)
		assert.Equal(t, "test-user", headers["X-User"])
	})

	t.Run("invalid template", func(t *testing.T) {
		// Test invalid template
		err := h.AddHeader("echo.example.com", "X-Invalid", "{{.Invalid}}")
		assert.Error(t, err)
	})

	t.Run("non-existent upstream", func(t *testing.T) {
		// Test non-existent upstream
		headers, err := h.GetHeaders("nonexistent", ident)
		assert.NoError(t, err)
		assert.Empty(t, headers)
	})

	t.Run("named template", func(t *testing.T) {
		// Add a named template
		err := h.templates.AddTemplateString("user-info", "User:{{.CommonName}};Roles:{{join .Roles \"; \"}}")
		assert.NoError(t, err)

		// Use the named template in a header - context will be added automatically
		err = h.AddHeader("echo.example.com", "X-User-Info", "{{template \"user-info\"}}")
		assert.NoError(t, err)

		// Test getting headers
		headers, err := h.GetHeaders("echo.example.com", ident)
		assert.NoError(t, err)
		assert.Equal(t, "User:test-user;Roles:role1; role2", headers["X-User-Info"])
	})

	t.Run("multiple templates", func(t *testing.T) {
		// Add templates
		err := h.templates.AddTemplateString("user", "User:{{.CommonName}}")
		assert.NoError(t, err)
		err = h.templates.AddTemplateString("role", "Role:{{join .Roles \"; \"}}")
		assert.NoError(t, err)

		// Use multiple templates in a header
		err = h.AddHeader("echo.example.com", "X-User-Role", "{{template \"user\"}}|{{template \"role\"}}")
		assert.NoError(t, err)

		// Test getting headers
		headers, err := h.GetHeaders("echo.example.com", ident)
		assert.NoError(t, err)
		assert.Equal(t, "User:test-user|Role:role1; role2", headers["X-User-Role"])
	})

	t.Run("nested templates", func(t *testing.T) {
		// Add base templates
		err := h.templates.AddTemplateString("user", "User:{{.CommonName}}")
		assert.NoError(t, err)
		err = h.templates.AddTemplateString("role", "Role:{{join .Roles \"; \"}}")
		assert.NoError(t, err)

		// Add a template that uses other templates
		err = h.templates.AddTemplateString("user-role", "{{template \"user\"}}|{{template \"role\"}}")
		assert.NoError(t, err)

		// Use the nested template in a header
		err = h.AddHeader("echo.example.com", "X-User-Role-Nested", "{{template \"user-role\"}}")
		assert.NoError(t, err)

		// Test getting headers
		headers, err := h.GetHeaders("echo.example.com", ident)
		assert.NoError(t, err)
		assert.Equal(t, "User:test-user|Role:role1; role2", headers["X-User-Role-Nested"])
	})

	t.Run("sequential templates", func(t *testing.T) {
		// Add base templates
		err := h.templates.AddTemplateString("user", "User:{{.CommonName}}")
		assert.NoError(t, err)
		err = h.templates.AddTemplateString("role", "Role:{{join .Roles \"; \"}}")
		assert.NoError(t, err)
		err = h.templates.AddTemplateString("auth", "Auth:{{join .Auths \"; \"}}")
		assert.NoError(t, err)

		// Add a template that uses multiple templates sequentially
		userRef := h.templates.CreateTemplateReference("user")
		roleRef := h.templates.CreateTemplateReference("role")
		authRef := h.templates.CreateTemplateReference("auth")
		err = h.templates.AddTemplateString("user-role-auth", userRef + roleRef + authRef)
		assert.NoError(t, err)

		// Use the sequential template in a header
		err = h.AddHeader("echo.example.com", "X-User-Role-Auth", "{{template \"user-role-auth\"}}")
		assert.NoError(t, err)

		// Test getting headers
		headers, err := h.GetHeaders("echo.example.com", ident)
		assert.NoError(t, err)
		assert.Equal(t, "User:test-userRole:role1; role2Auth:auth1; auth2", headers["X-User-Role-Auth"])
	})

	t.Run("template functions", func(t *testing.T) {
		// Test join function
		err := h.AddHeader("echo.example.com", "X-Roles", "{{join .Roles \"; \"}}")
		assert.NoError(t, err)

		// Test comma function
		err = h.AddHeader("echo.example.com", "X-Groups", "{{comma .Groups}}")
		assert.NoError(t, err)

		// Test space function
		err = h.AddHeader("echo.example.com", "X-Auth", "{{space .Auths}}")
		assert.NoError(t, err)

		// Test getting headers
		headers, err := h.GetHeaders("echo.example.com", ident)
		assert.NoError(t, err)
		assert.Equal(t, "role1; role2", headers["X-Roles"])
		assert.Equal(t, "group1,group2", headers["X-Groups"])
		assert.Equal(t, "auth1 auth2", headers["X-Auth"])
	})

	t.Run("multiple headers", func(t *testing.T) {
		// Add multiple headers for same upstream
		err := h.AddHeader("multi.example.com", "X-User", "{{.CommonName}}")
		assert.NoError(t, err)

		err = h.AddHeader("multi.example.com", "X-Roles", "{{join .Roles \"; \"}}")
		assert.NoError(t, err)

		// Test getting multiple headers
		headers, err := h.GetHeaders("multi.example.com", ident)
		assert.NoError(t, err)
		assert.Equal(t, "test-user", headers["X-User"])
		assert.Equal(t, "role1; role2", headers["X-Roles"])
	})
}

func TestCommonHeaders(t *testing.T) {
	logger := logger.New("header", logger.LevelInfo)
	injector := NewHeaderInjector(logger)

	// Add common headers
	err := injector.AddCommonHeader("cn", "test-upstream", "X-Common-CN")
	if err != nil {
		t.Fatalf("Failed to add CN header: %v", err)
	}

	err = injector.AddCommonHeader("groups", "test-upstream", "X-Common-Groups")
	if err != nil {
		t.Fatalf("Failed to add groups header: %v", err)
	}

	identity := &identity.Identity{
		CommonName: "test-user",
		Groups:     []string{"group1", "group2"},
	}

	// Get headers for test-upstream
	headers, err := injector.GetHeaders("test-upstream", identity)
	if err != nil {
		t.Fatalf("Failed to get headers: %v", err)
	}

	// Verify headers
	if headers["X-Common-CN"] != "test-user" {
		t.Errorf("Expected X-Common-CN header to be 'test-user', got '%s'", headers["X-Common-CN"])
	}

	if headers["X-Common-Groups"] != "group1,group2" {
		t.Errorf("Expected X-Common-Groups header to be 'group1,group2', got '%s'", headers["X-Common-Groups"])
	}
}

func TestAppendUnique(t *testing.T) {
	// Test cases
	tests := []struct {
		name     string
		slice    []string
		items    []string
		expected []string
	}{
		{
			name:     "append to empty slice",
			slice:    []string{},
			items:    []string{"test"},
			expected: []string{"test"},
		},
		{
			name:     "append unique item",
			slice:    []string{"a", "b"},
			items:    []string{"c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "append duplicate item",
			slice:    []string{"a", "b", "c"},
			items:    []string{"b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "append multiple items",
			slice:    []string{"a", "b"},
			items:    []string{"c", "d", "b"},
			expected: []string{"a", "b", "c", "d"},
		},
	}

	// Run test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(map[string]bool)
			result := appendUnique(tc.slice, tc.items, seen)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}
