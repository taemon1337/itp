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
	logger := setupTestLogger()
	r := NewRouter(logger, false)
	r.SetEchoUpstream("echo.test", "localhost:8080")
	name, addr := r.GetEchoUpstream()
	assert.Equal(t, "echo.test", name)
	assert.Equal(t, "localhost:8080", addr)
}

func TestResolveDestination(t *testing.T) {
	tests := []struct {
		name          string
		serverName    string
		staticRoutes  map[string]string
		echoName      string
		echoAddr      string
		useDNS        bool
		expectedDest  string
		expectedError string
	}{
		{
			name:         "echo upstream direct",
			serverName:   "echo.test",
			echoName:     "echo.test",
			echoAddr:     "localhost:8080",
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
			name:       "static route to echo",
			serverName: "example.com",
			staticRoutes: map[string]string{
				"example.com": "echo.test",
			},
			echoName:     "echo.test",
			echoAddr:     "localhost:8080",
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
			r.SetEchoUpstream(tt.echoName, tt.echoAddr)

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
