package router

import (
	"fmt"
	"net"
	"strings"
)

// Router handles destination routing
type Router struct {
	useDNS        bool
	staticRoutes  map[string]string
	routePatterns map[string]string
	echoName      string
	echoAddr      string
}

// NewRouter creates a new router instance
func NewRouter(useDNS bool) *Router {
	return &Router{
		useDNS:        useDNS,
		staticRoutes:  make(map[string]string),
		routePatterns: make(map[string]string),
	}
}

// SetEchoUpstream configures the echo upstream with a name and address
func (r *Router) SetEchoUpstream(name, addr string) {
	r.echoName = name
	r.echoAddr = addr
}

// ResolveDestination resolves the final destination for a server name
func (r *Router) ResolveDestination(serverName string) (string, error) {
	// Check if destination is the echo upstream
	if r.echoName != "" && serverName == r.echoName {
		return r.echoAddr, nil
	}

	// Check static routes first
	if dest, ok := r.staticRoutes[serverName]; ok {
		// Check if route points to echo upstream
		if r.echoName != "" && dest == r.echoName {
			return r.echoAddr, nil
		}
		return dest, nil
	}

	// Check route patterns
	for pattern, dest := range r.routePatterns {
		if strings.Contains(serverName, pattern) {
			// Check if route points to echo upstream
			if r.echoName != "" && dest == r.echoName {
				return r.echoAddr, nil
			}
			return dest, nil
		}
	}

	// Use DNS if enabled
	if r.useDNS {
		// Try to resolve as hostname:port
		host, port, err := net.SplitHostPort(serverName)
		if err != nil {
			// If no port specified, use default HTTPS port
			host = serverName
			port = "443"
		}

		addrs, err := net.LookupHost(host)
		if err != nil {
			return "", fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}
		if len(addrs) == 0 {
			return "", fmt.Errorf("no addresses found for %s", host)
		}

		return net.JoinHostPort(addrs[0], port), nil
	}

	return "", fmt.Errorf("no route found for %s", serverName)
}

// AddStaticRoute adds a static route mapping
func (r *Router) AddStaticRoute(src, dest string) {
	r.staticRoutes[src] = dest
}

// AddRoutePattern adds a pattern-based route
func (r *Router) AddRoutePattern(pattern, dest string) {
	r.routePatterns[pattern] = dest
}