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
	routes       map[string][]*Route // Stores full route information including paths
	logger       *logger.Logger
}

// NewRouter creates a new router instance
func NewRouter(logger *logger.Logger, useDNS bool) *Router {
	return &Router{
		useDNS:       useDNS,
		staticRoutes: make(map[string]string),
		routes:       make(map[string][]*Route),
		logger:       logger,
	}
}

// SetEchoUpstream configures the echo upstream with a name and address.
// This adds a static route from the echo name to its address.
func (r *Router) SetEchoUpstream(name, addr string) {
	r.staticRoutes[name] = addr
	r.logger.Info("Echo upstream configured with name=%s addr=%s", name, addr)
}

// GetRoute returns the first route configuration for a given server name
func (r *Router) GetRoute(serverName string) (*Route, bool) {
	routes, ok := r.routes[serverName]
	if !ok || len(routes) == 0 {
		return nil, false
	}
	// Return the first route for backward compatibility
	return routes[0], true
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
// HasRoutesForServer checks if there are any routes defined for a server
func (r *Router) HasRoutesForServer(serverName string) bool {
	r.logger.Debug("Checking for routes for server: %s", serverName)
	routes, hasRoutes := r.routes[serverName]
	if !hasRoutes {
		r.logger.Debug("No routes found for server %s", serverName)
		return false
	}
	r.logger.Debug("Found %d routes for server %s", len(routes), serverName)
	return true
}

func (r *Router) ResolveDestination(serverName string, path string) (string, string, error) {
	r.logger.Debug("Resolving destination for server name: %s with path: %s (len: %d)", serverName, path, len(path))

	// Debug log all routes
	r.logger.Debug("Current routes:")
	for src, routes := range r.routes {
		for _, route := range routes {
			r.logger.Debug("  %s -> %s (SourcePath: %s, DestPath: %s)", src, route.Destination, route.SourcePath, route.DestPath)
		}
	}

	// Check if we have routes for this server
	routes, hasRoutes := r.routes[serverName]
	if !hasRoutes {
		r.logger.Debug("No routes found for server %s", serverName)
		return "", "", fmt.Errorf("no route found for %s", serverName)
	}

	// If path is empty or just "/", try to find a default route first
	if path == "" || path == "/" {
		r.logger.Debug("Empty or root path, looking for default route")
		for _, route := range routes {
			if route.SourcePath == "" {
				dest := route.Destination
				// If dest is another static route, follow it
				if finalDest, ok := r.staticRoutes[dest]; ok {
					r.logger.Debug("Following static route %s -> %s -> %s", serverName, dest, finalDest)
					dest = finalDest
				}
				r.logger.Debug("Using default route to destination %s", dest)
				return dest, path, nil
			}
		}
		// If no default route, try path-based routes
		r.logger.Debug("No default route found, trying path-based routes")
	}

	// Try to match a path-based route
	for _, route := range routes {
		if route.SourcePath != "" {
			r.logger.Debug("Checking if path %s matches route source path %s", path, route.SourcePath)
			if strings.HasPrefix(path, route.SourcePath) {
				dest := route.Destination
				// If dest is another static route, follow it
				if finalDest, ok := r.staticRoutes[dest]; ok {
					r.logger.Debug("Following static route %s -> %s -> %s", serverName, dest, finalDest)
					dest = finalDest
				}

				// Handle path transformation
				if route.DestPath != "" {
					// Replace source path prefix with destination path prefix
					newPath := strings.Replace(path, route.SourcePath, route.DestPath, 1)
					r.logger.Debug("Path transformed: %s -> %s", path, newPath)
					return dest, newPath, nil
				} else {
					// Strip the source path prefix
					newPath := strings.TrimPrefix(path, route.SourcePath)
					if !strings.HasPrefix(newPath, "/") {
						newPath = "/" + newPath
					}
					r.logger.Debug("Path stripped: %s -> %s", path, newPath)
					return dest, newPath, nil
				}
			}
			r.logger.Debug("Path %s does not match route source path %s", path, route.SourcePath)
		}
	}

	// If no path-based route matched, try to find a route without a path
	for _, route := range routes {
		if route.SourcePath == "" {
			dest := route.Destination
			// If dest is another static route, follow it
			if finalDest, ok := r.staticRoutes[dest]; ok {
				r.logger.Debug("Following static route %s -> %s -> %s", serverName, dest, finalDest)
				dest = finalDest
			}
			r.logger.Debug("Using direct destination %s with path %s", dest, path)
			return dest, path, nil
		}
	}

	r.logger.Debug("No matching route found for %s with path %s", serverName, path)
	return "", "", fmt.Errorf("no route found")

	// Use DNS if enabled and no static route found
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

// AddStaticRoute adds a static route mapping with optional path prefixes and TLS preservation
func (r *Router) AddStaticRoute(src, dest string) {
	r.logger.Debug("Adding static route - src: %s, dest: %s", src, dest)

	// Parse source and handle paths
	srcParts := strings.Split(src, "/")
	srcHost := srcParts[0]
	var srcPath string
	if len(srcParts) > 1 {
		srcPath = "/" + strings.Join(srcParts[1:], "/")
	}

	// Check if destination should preserve TLS verification and extract the actual destination
	preserveTLS := false
	destination := dest
	if strings.HasPrefix(dest, "tls://") {
		preserveTLS = true
		destination = strings.TrimPrefix(dest, "tls://")
	}

	// Parse destination and handle paths
	destParts := strings.Split(destination, "/")
	destHost := destParts[0]
	var destPath string
	if len(destParts) > 1 {
		destPath = "/" + strings.Join(destParts[1:], "/")
	}

	// Log the parsing steps for debugging
	r.logger.Debug("Parsing route - src: %s (host: %s, path: %s), dest: %s (host: %s, path: %s)", 
		src, srcHost, srcPath, dest, destHost, destPath)

	// Create the route with path information
	route := &Route{
		Source:      srcHost,
		Destination: destHost,
		SourcePath:  srcPath,
		DestPath:    destPath,
		PreserveTLS: preserveTLS,
	}

	// Store the route
	if _, exists := r.routes[srcHost]; !exists {
		r.routes[srcHost] = make([]*Route, 0)
	}
	r.routes[srcHost] = append(r.routes[srcHost], route)

	// Store the static route if there's no path
	if srcPath == "" {
		r.staticRoutes[srcHost] = destHost
	}

	r.logger.Info("Added static route %s -> %s with paths %s -> %s", 
		route.Source, route.Destination, route.SourcePath, route.DestPath)
}
