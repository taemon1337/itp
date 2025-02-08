package router

import (
	"testing"

	"github.com/itp/pkg/logger"
	"github.com/stretchr/testify/assert"
)

// setupTestLogger creates a logger for testing
func setupTestLogger() *logger.Logger {
	return logger.New("router", logger.LevelDebug)
}

func TestNewRouter(t *testing.T) {
	tests := []struct {
		name   string
		useDNS bool
	}{
		{
			name:   "with DNS routing enabled",
			useDNS: true,
		},
		{
			name:   "with DNS routing disabled",
			useDNS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupTestLogger()
			r := NewRouter(logger, tt.useDNS)
			assert.Equal(t, tt.useDNS, r.useDNS)
			assert.NotNil(t, r.staticRoutes)
		})
	}
}

func TestSetEchoUpstream(t *testing.T) {
	tests := []struct {
		name           string
		echoName       string
		echoAddr       string
		expectedName   string
		expectedAddr   string
		existingRoutes map[string]string
	}{
		{
			name:         "simple echo setup",
			echoName:     "echo.test",
			echoAddr:     "localhost:8080",
			expectedName: "echo.test",
			expectedAddr: "localhost:8080",
		},
		{
			name:     "echo with existing routes",
			echoName: "echo.test",
			echoAddr: "localhost:8080",
			existingRoutes: map[string]string{
				"other.test": "other:8080",
			},
			expectedName: "echo.test",
			expectedAddr: "localhost:8080",
		},
		{
			name:     "multiple echo endpoints",
			echoName: "echo2.test",
			echoAddr: "localhost:8082",
			existingRoutes: map[string]string{
				"echo1.test": "localhost:8081",
			},
			expectedName: "echo1.test",
			expectedAddr: "localhost:8081",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupTestLogger()
			r := NewRouter(logger, false)

			// Add any existing routes
			for k, v := range tt.existingRoutes {
				r.AddStaticRoute(k, v)
			}

			// Set the echo upstream
			r.SetEchoUpstream(tt.echoName, tt.echoAddr)

			// Verify the route was added
			dest, ok := r.staticRoutes[tt.echoName]
			assert.True(t, ok)
			assert.Equal(t, tt.echoAddr, dest)

			// Get echo upstream and verify
			name, addr := r.GetEchoUpstream()
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedAddr, addr)
		})
	}
}

func TestResolveDestination(t *testing.T) {
	tests := []struct {
		name          string
		serverName    string
		staticRoutes  map[string]string
		useDNS        bool
		expectedDest  string
		expectedError string
	}{
		{
			name:         "direct route",
			serverName:   "echo.test",
			staticRoutes: map[string]string{
				"echo.test": "localhost:8080",
			},
			expectedDest: "localhost:8080",
		},
		{
			name:       "static route",
			serverName: "example.com",
			staticRoutes: map[string]string{
				"example.com": "10.0.0.1:443",
			},
			expectedDest: "10.0.0.1:443",
		},
		{
			name:       "chained route",
			serverName: "example.com",
			staticRoutes: map[string]string{
				"example.com": "echo.test",
				"echo.test":   "localhost:8080",
			},
			expectedDest: "localhost:8080",
		},
		{
			name:          "no route found with DNS disabled",
			serverName:    "unknown.example.com",
			useDNS:        false,
			expectedError: "no route found for unknown.example.com",
		},
		{
			name:          "no route found with DNS enabled but invalid hostname",
			serverName:    "invalid..hostname",
			useDNS:        true,
			expectedError: "DNS lookup failed for invalid..hostname",
		},
		{
			name:         "route via DNS when enabled",
			serverName:   "localhost:8443",
			useDNS:       true,
			expectedDest: "127.0.0.1:8443",
		},
		{
			name:         "route via DNS with default port",
			serverName:   "localhost",
			useDNS:       true,
			expectedDest: "127.0.0.1:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupTestLogger()
			r := NewRouter(logger, tt.useDNS)

			for src, dest := range tt.staticRoutes {
				r.AddStaticRoute(src, dest)
			}

			dest, err := r.ResolveDestination(tt.serverName)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDest, dest)
			}
		})
	}
}

func TestAddStaticRoute(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		dest     string
		expected string
	}{
		{
			name:     "basic route",
			src:      "example.com",
			dest:     "10.0.0.1:443",
			expected: "10.0.0.1:443",
		},
		{
			name:     "route with port",
			src:      "example.com:8443",
			dest:     "10.0.0.1:8443",
			expected: "10.0.0.1:8443",
		},
		{
			name:     "route to echo",
			src:      "example.com",
			dest:     "echo.test",
			expected: "echo.test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupTestLogger()
			r := NewRouter(logger, false)
			r.AddStaticRoute(tt.src, tt.dest)
			assert.Equal(t, tt.expected, r.staticRoutes[tt.src])
		})
	}
}
