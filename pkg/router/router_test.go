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

func TestResolveDestinationWithPorts(t *testing.T) {
	tests := []struct {
		name           string
		routes         map[string]string
		serverName     string
		path           string
		expectedDest   string
		expectedPath   string
		expectedError  string
	}{
		{
			name: "destination with port",
			routes: map[string]string{
				"app.example.com": "backend.cluster.local:8080",
			},
			serverName:    "app.example.com",
			path:          "/users",
			expectedDest:  "backend.cluster.local:8080",
			expectedPath:  "/users",
		},
		{
			name: "path routing with port",
			routes: map[string]string{
				"app.example.com/api": "backend.cluster.local:8080/v1",
			},
			serverName:    "app.example.com",
			path:          "/api/users",
			expectedDest:  "backend.cluster.local:8080",
			expectedPath:  "/v1/users",
		},
		{
			name: "chained routes with port",
			routes: map[string]string{
				"app.example.com": "backend.cluster.local:8080",
				"backend.cluster.local:8080": "final.cluster.local:9090",
			},
			serverName:    "app.example.com",
			path:          "/users",
			expectedDest:  "final.cluster.local:9090",
			expectedPath:  "/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRouter(setupTestLogger(), false)
			for src, dest := range tt.routes {
				r.AddStaticRoute(src, dest)
			}

			dest, path, err := r.ResolveDestination(tt.serverName, tt.path)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDest, dest)
				assert.Equal(t, tt.expectedPath, path)
			}
		})
	}
}

func TestResolveDestinationWithPaths(t *testing.T) {
	tests := []struct {
		name           string
		routes         map[string]string
		serverName     string
		path           string
		expectedDest   string
		expectedPath   string
		expectedError  string
	}{
		{
			name: "path prefix replacement",
			routes: map[string]string{
				"echo.example.com/app": "upstream.cluster.local/api",
			},
			serverName:    "echo.example.com",
			path:          "/app/v1/users",
			expectedDest:  "upstream.cluster.local",
			expectedPath:  "/api/v1/users",
		},
		{
			name: "path prefix stripping",
			routes: map[string]string{
				"echo.example.com/app": "upstream.cluster.local",
			},
			serverName:    "echo.example.com",
			path:          "/app/v1/users",
			expectedDest:  "upstream.cluster.local",
			expectedPath:  "/v1/users",
		},
		{
			name: "no path in route",
			routes: map[string]string{
				"echo.example.com": "upstream.cluster.local",
			},
			serverName:    "echo.example.com",
			path:          "/v1/users",
			expectedDest:  "upstream.cluster.local",
			expectedPath:  "/v1/users",
		},
		{
			name: "path does not match prefix",
			routes: map[string]string{
				"echo.example.com/app": "upstream.cluster.local/api",
			},
			serverName:    "echo.example.com",
			path:          "/v1/users",
			expectedDest:  "echo.example.com",
			expectedPath:  "/v1/users",
			expectedError: "no route found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRouter(setupTestLogger(), false)
			for src, dest := range tt.routes {
				r.AddStaticRoute(src, dest)
			}

			dest, path, err := r.ResolveDestination(tt.serverName, tt.path)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDest, dest)
				assert.Equal(t, tt.expectedPath, path)
			}
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
		{
			name:       "TLS route with path",
			serverName: "secure.example.com",
			staticRoutes: map[string]string{
				"secure.example.com": "tls://api.external.com:8443/v1",
			},
			expectedDest: "api.external.com:8443",
		},
		{
			name:       "TLS route without port",
			serverName: "secure.example.com",
			staticRoutes: map[string]string{
				"secure.example.com": "tls://api.external.com",
			},
			expectedDest: "api.external.com",
		},
		{
			name:       "chained TLS route",
			serverName: "secure.example.com",
			staticRoutes: map[string]string{
				"secure.example.com": "tls://api.external.com:8443",
				"api.external.com:8443": "final.external.com:9443",
			},
			expectedDest: "final.external.com:9443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := setupTestLogger()
			r := NewRouter(logger, tt.useDNS)

			for src, dest := range tt.staticRoutes {
				r.AddStaticRoute(src, dest)
			}

			dest, _, err := r.ResolveDestination(tt.serverName, "")
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

func TestAddStaticRouteWithPaths(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		destination    string
		expectedRoute  *Route
	}{
		{
			name:        "with path prefixes",
			source:      "echo.example.com/app",
			destination: "upstream.cluster.local/api",
			expectedRoute: &Route{
				Source:      "echo.example.com",
				SourcePath:  "/app",
				Destination: "upstream.cluster.local",
				DestPath:    "/api",
			},
		},
		{
			name:        "with source path only",
			source:      "echo.example.com/app",
			destination: "upstream.cluster.local",
			expectedRoute: &Route{
				Source:      "echo.example.com",
				SourcePath:  "/app",
				Destination: "upstream.cluster.local",
				DestPath:    "",
			},
		},
		{
			name:        "no paths",
			source:      "echo.example.com",
			destination: "upstream.cluster.local",
			expectedRoute: &Route{
				Source:      "echo.example.com",
				SourcePath:  "",
				Destination: "upstream.cluster.local",
				DestPath:    "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRouter(setupTestLogger(), false)
			r.AddStaticRoute(tt.source, tt.destination)

			// Verify the route was stored correctly
			routes := r.routes[tt.expectedRoute.Source]
			assert.NotNil(t, routes)
			assert.Equal(t, 1, len(routes), "Expected exactly one route")
			route := routes[0]
			assert.Equal(t, tt.expectedRoute.Source, route.Source)
			assert.Equal(t, tt.expectedRoute.SourcePath, route.SourcePath)
			assert.Equal(t, tt.expectedRoute.Destination, route.Destination)
			assert.Equal(t, tt.expectedRoute.DestPath, route.DestPath)

			// Verify the static route was also stored
			dest := r.staticRoutes[tt.expectedRoute.Source]
			assert.Equal(t, tt.expectedRoute.Destination, dest)
		})
	}
}

func TestAddStaticRouteWithTLS(t *testing.T) {
	tests := []struct {
		name           string
		source         string
		destination    string
		expectedRoute  *Route
	}{
		{
			name:        "preserve TLS verification",
			source:      "app.example.com",
			destination: "tls://api.external.com:8443",
			expectedRoute: &Route{
				Source:      "app.example.com",
				Destination: "api.external.com:8443",
				PreserveTLS: true,
			},
		},
		{
			name:        "preserve TLS with path",
			source:      "app.example.com/api",
			destination: "tls://api.external.com:8443/v1",
			expectedRoute: &Route{
				Source:      "app.example.com",
				SourcePath:  "/api",
				Destination: "api.external.com:8443",
				DestPath:    "/v1",
				PreserveTLS: true,
			},
		},
		{
			name:        "normal route without TLS preservation",
			source:      "app.example.com",
			destination: "backend.cluster.local:8443",
			expectedRoute: &Route{
				Source:      "app.example.com",
				Destination: "backend.cluster.local:8443",
				PreserveTLS: false,
			},
		},
		{
			name:        "TLS with multiple path segments",
			source:      "app.example.com/api/v2",
			destination: "tls://api.external.com:8443/v1/public",
			expectedRoute: &Route{
				Source:      "app.example.com",
				SourcePath:  "/api/v2",
				Destination: "api.external.com:8443",
				DestPath:    "/v1/public",
				PreserveTLS: true,
			},
		},
		{
			name:        "TLS with trailing slash in path",
			source:      "app.example.com/api/",
			destination: "tls://api.external.com:8443/v1/",
			expectedRoute: &Route{
				Source:      "app.example.com",
				SourcePath:  "/api/",
				Destination: "api.external.com:8443",
				DestPath:    "/v1/",
				PreserveTLS: true,
			},
		},
		{
			name:        "TLS without port number",
			source:      "app.example.com",
			destination: "tls://api.external.com/v1",
			expectedRoute: &Route{
				Source:      "app.example.com",
				Destination: "api.external.com",
				DestPath:    "/v1",
				PreserveTLS: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRouter(setupTestLogger(), false)
			r.AddStaticRoute(tt.source, tt.destination)

			// Verify the route was stored correctly
			routes := r.routes[tt.expectedRoute.Source]
			assert.NotNil(t, routes)
			assert.Equal(t, 1, len(routes), "Expected exactly one route")
			route := routes[0]
			assert.Equal(t, tt.expectedRoute.Source, route.Source)
			assert.Equal(t, tt.expectedRoute.SourcePath, route.SourcePath)
			assert.Equal(t, tt.expectedRoute.Destination, route.Destination)
			assert.Equal(t, tt.expectedRoute.DestPath, route.DestPath)
			assert.Equal(t, tt.expectedRoute.PreserveTLS, route.PreserveTLS)

			// Verify the static route was also stored
			dest := r.staticRoutes[tt.expectedRoute.Source]
			assert.Equal(t, tt.expectedRoute.Destination, dest)
		})
	}
}

func TestPreserveTLSRoute(t *testing.T) {
	r := NewRouter(setupTestLogger(), false)

	// Add a route with PreserveTLS
	r.AddStaticRoute("app.example.com", "tls://api.external.com:8443")

	// Get the route configuration
	route, ok := r.GetRoute("app.example.com")
	assert.True(t, ok, "Route should exist")
	assert.NotNil(t, route, "Route should not be nil")

	// Verify PreserveTLS flag is set
	assert.True(t, route.PreserveTLS, "PreserveTLS should be true")
	assert.Equal(t, "api.external.com:8443", route.Destination, "Destination should be set correctly")

	// Add a normal route without PreserveTLS
	r.AddStaticRoute("app2.example.com", "backend.internal:8443")

	// Verify PreserveTLS is not set
	route, ok = r.GetRoute("app2.example.com")
	assert.True(t, ok, "Route should exist")
	assert.NotNil(t, route, "Route should not be nil")
	assert.False(t, route.PreserveTLS, "PreserveTLS should be false")
	assert.Equal(t, "backend.internal:8443", route.Destination, "Destination should be set correctly")
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
