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
	echoName     string
	echoAddr     string
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

// SetEchoUpstream configures the echo upstream with a name and address
func (r *Router) SetEchoUpstream(name, addr string) {
	r.echoName = name
	r.echoAddr = addr
	r.logger.Info("Echo upstream configured with name=%s addr=%s", name, addr)
}

// GetEchoUpstream returns the echo upstream name and address
func (r *Router) GetEchoUpstream() (string, string) {
	return r.echoName, r.echoAddr
}

// ResolveDestination resolves the final destination for a server name
func (r *Router) ResolveDestination(serverName string) (string, error) {
	r.logger.Debug("Resolving destination for server name: %s", serverName)

	// Check if destination is the echo upstream
	if r.echoName != "" && serverName == r.echoName {
		r.logger.Debug("Using echo upstream for %s -> %s", serverName, r.echoAddr)
		return r.echoAddr, nil
	}

	// Check static routes first
	if dest, ok := r.staticRoutes[serverName]; ok {
		// Check if route points to echo upstream
		if r.echoName != "" && dest == r.echoName {
			r.logger.Debug("Static route %s points to echo upstream -> %s", serverName, r.echoAddr)
			return r.echoAddr, nil
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