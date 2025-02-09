package router

import (
	"fmt"
	"net"
	"strings"

	"github.com/itp/pkg/logger"
)

// Router handles destination routing
type Router struct {
	useDNS       bool
	staticRoutes map[string]string
	routes       map[string]*Route // Stores full route information including paths
	logger       *logger.Logger
}

// NewRouter creates a new router instance
func NewRouter(logger *logger.Logger, useDNS bool) *Router {
	return &Router{
		useDNS:       useDNS,
		staticRoutes: make(map[string]string),
		routes:       make(map[string]*Route),
		logger:       logger,
	}
}

// SetEchoUpstream configures the echo upstream with a name and address.
// This adds a static route from the echo name to its address.
func (r *Router) SetEchoUpstream(name, addr string) {
	r.staticRoutes[name] = addr
	r.logger.Info("Echo upstream configured with name=%s addr=%s", name, addr)
}

// GetEchoUpstream returns the echo upstream name and address.
// Returns the first echo endpoint added.
func (r *Router) GetEchoUpstream() (string, string) {
	var firstEchoName, firstEchoAddr string
	for name, addr := range r.staticRoutes {
		// Consider it an echo endpoint if its address isn't used as another route's name
		if _, exists := r.staticRoutes[addr]; !exists {
			// If this is the first echo endpoint we've found, remember it
			if firstEchoName == "" {
				firstEchoName = name
				firstEchoAddr = addr
			}
			// If this matches the pattern of being an echo endpoint (e.g., starts with 'echo')
			if strings.HasPrefix(name, "echo") {
				return name, addr
			}
		}
	}
	// If we didn't find an echo.* endpoint, return the first valid endpoint
	if firstEchoName != "" {
		return firstEchoName, firstEchoAddr
	}
	return "", ""
}

// ResolveDestination resolves the final destination for a server name and optional path
func (r *Router) ResolveDestination(serverName string, path string) (string, string, error) {
	r.logger.Debug("Resolving destination for server name: %s", serverName)

	// Check static routes first
	if route, hasRoute := r.routes[serverName]; hasRoute && route.SourcePath != "" && path != "" {
		// If we have a path-based route, check if the path matches
		if strings.HasPrefix(path, route.SourcePath) {
			// Get the destination from static routes
			dest, ok := r.staticRoutes[serverName]
			if !ok {
				return serverName, path, fmt.Errorf("no route found")
			}

			// If dest is another static route, follow it
			if finalDest, ok := r.staticRoutes[dest]; ok {
				r.logger.Debug("Following static route %s -> %s -> %s", serverName, dest, finalDest)
				dest = finalDest
			}

			// Handle path transformation
			if route.DestPath != "" {
				// Replace source path prefix with destination path prefix
				newPath := strings.Replace(path, route.SourcePath, route.DestPath, 1)
				return dest, newPath, nil
			} else {
				// Strip the source path prefix
				newPath := strings.TrimPrefix(path, route.SourcePath)
				if !strings.HasPrefix(newPath, "/") {
					newPath = "/" + newPath
				}
				return dest, newPath, nil
			}
		} else {
			// Path doesn't match the route's source path
			return serverName, path, fmt.Errorf("no route found")
		}
	}

	// No path-based route, check static routes
	if dest, ok := r.staticRoutes[serverName]; ok {
		// If dest is another static route, follow it
		if finalDest, ok := r.staticRoutes[dest]; ok {
			r.logger.Debug("Following static route %s -> %s -> %s", serverName, dest, finalDest)
			return finalDest, path, nil
		}
		r.logger.Debug("Using static route %s -> %s", serverName, dest)
		return dest, path, nil
	}

	// Use DNS if enabled
	if r.useDNS {
		r.logger.Debug("No static route found for %s, attempting DNS resolution", serverName)
		// Try to resolve as hostname:port
		host, port, err := net.SplitHostPort(serverName)
		if err != nil {
			// If no port specified, use default HTTPS port
			host = serverName
			port = "443"
			r.logger.Debug("No port specified in %s, using default port %s", serverName, port)
		}

		addrs, err := net.LookupHost(host)
		if err != nil {
			r.logger.Error("DNS lookup failed for %s: %v", host, err)
			return "", "", fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}
		if len(addrs) == 0 {
			r.logger.Error("No addresses found for %s", host)
			return "", "", fmt.Errorf("no addresses found for %s", host)
		}

		// Use first resolved address
		dest := net.JoinHostPort(addrs[0], port)
		r.logger.Debug("DNS resolved %s -> %s", serverName, dest)
		return dest, path, nil
	}

	r.logger.Error("No route found for %s and DNS resolution disabled", serverName)
	return "", "", fmt.Errorf("no route found for %s", serverName)
}

// AddStaticRoute adds a static route mapping with optional path prefixes
func (r *Router) AddStaticRoute(src, dest string) {
	// Parse source and destination for paths
	srcParts := strings.SplitN(src, "/", 2)
	destParts := strings.SplitN(dest, "/", 2)

	// Create the route with path information
	route := &Route{
		Source:      srcParts[0],
		Destination: destParts[0],
	}

	// Add path prefixes if present
	if len(srcParts) > 1 {
		route.SourcePath = "/" + srcParts[1]
	}
	if len(destParts) > 1 {
		route.DestPath = "/" + destParts[1]
	}

	// Store both the simple mapping and the full route
	r.staticRoutes[srcParts[0]] = destParts[0]
	r.routes[srcParts[0]] = route

	r.logger.Info("Added static route %s -> %s with paths %s -> %s", 
		route.Source, route.Destination, route.SourcePath, route.DestPath)
}
