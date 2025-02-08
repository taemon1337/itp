package router

import (
	"fmt"
	"net"

	"github.com/itp/pkg/logger"
)

// Router handles destination routing
type Router struct {
	useDNS       bool
	staticRoutes map[string]string
	logger       *logger.Logger
}

// NewRouter creates a new router instance
func NewRouter(logger *logger.Logger, useDNS bool) *Router {
	return &Router{
		useDNS:       useDNS,
		staticRoutes: make(map[string]string),
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
// The name will be the first key found that maps to an echo address.
func (r *Router) GetEchoUpstream() (string, string) {
	for name, addr := range r.staticRoutes {
		// Consider it an echo endpoint if the name is used as a destination
		if _, exists := r.staticRoutes[addr]; !exists {
			return name, addr
		}
	}
	return "", ""
}

// ResolveDestination resolves the final destination for a server name
func (r *Router) ResolveDestination(serverName string) (string, error) {
	r.logger.Debug("Resolving destination for server name: %s", serverName)

	// Check static routes first
	if dest, ok := r.staticRoutes[serverName]; ok {
		// If dest is another static route, follow it
		if finalDest, ok := r.staticRoutes[dest]; ok {
			r.logger.Debug("Following static route %s -> %s -> %s", serverName, dest, finalDest)
			return finalDest, nil
		}
		r.logger.Debug("Using static route %s -> %s", serverName, dest)
		return dest, nil
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
			return "", fmt.Errorf("DNS lookup failed for %s: %w", host, err)
		}
		if len(addrs) == 0 {
			r.logger.Error("No addresses found for %s", host)
			return "", fmt.Errorf("no addresses found for %s", host)
		}

		// Use first resolved address
		dest := net.JoinHostPort(addrs[0], port)
		r.logger.Debug("DNS resolved %s -> %s", serverName, dest)
		return dest, nil
	}

	r.logger.Error("No route found for %s and DNS resolution disabled", serverName)
	return "", fmt.Errorf("no route found for %s", serverName)
}

// AddStaticRoute adds a static route mapping
func (r *Router) AddStaticRoute(src, dest string) {
	r.staticRoutes[src] = dest
	r.logger.Info("Added static route %s -> %s", src, dest)
}
