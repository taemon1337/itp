package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRouter(t *testing.T) {
	r := NewRouter(true)
	assert.NotNil(t, r)
	assert.True(t, r.useDNS)
	assert.NotNil(t, r.staticRoutes)
	assert.NotNil(t, r.routePatterns)
	assert.Empty(t, r.echoName)
	assert.Empty(t, r.echoAddr)
}

func TestSetEchoUpstream(t *testing.T) {
	r := NewRouter(false)
	r.SetEchoUpstream("echo.test", "localhost:8080")
	assert.Equal(t, "echo.test", r.echoName)
	assert.Equal(t, "localhost:8080", r.echoAddr)
}

func TestResolveDestination(t *testing.T) {
	tests := []struct {
		name           string
		serverName     string
		staticRoutes   map[string]string
		routePatterns  map[string]string
		echoName       string
		echoAddr       string
		expectedDest   string
		expectedError  bool
	}{
		{
			name:       "echo upstream direct",
			serverName: "echo.test",
			echoName:   "echo.test",
			echoAddr:   "localhost:8080",
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
			echoName:    "echo.test",
			echoAddr:    "localhost:8080",
			expectedDest: "localhost:8080",
		},
		{
			name:       "pattern route",
			serverName: "test.example.com",
			routePatterns: map[string]string{
				"example.com": "10.0.0.2:443",
			},
			expectedDest: "10.0.0.2:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRouter(false)
			r.SetEchoUpstream(tt.echoName, tt.echoAddr)
			
			for src, dest := range tt.staticRoutes {
				r.AddStaticRoute(src, dest)
			}
			
			for pattern, dest := range tt.routePatterns {
				r.AddRoutePattern(pattern, dest)
			}

			dest, err := r.ResolveDestination(tt.serverName)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDest, dest)
			}
		})
	}
}

func TestAddStaticRoute(t *testing.T) {
	r := NewRouter(false)
	r.AddStaticRoute("example.com", "10.0.0.1:443")
	assert.Equal(t, "10.0.0.1:443", r.staticRoutes["example.com"])
}

func TestAddRoutePattern(t *testing.T) {
	r := NewRouter(false)
	r.AddRoutePattern("example.com", "10.0.0.1:443")
	assert.Equal(t, "10.0.0.1:443", r.routePatterns["example.com"])
}
