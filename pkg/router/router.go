package router

import (
	"fmt"
	"net"
	"strings"
)

// Router handles the routing logic for the proxy
type Router struct {
	staticRoutes   map[string]string
	routePatterns  []RoutePattern
	defaultDNSMode bool
}

// NewRouter creates a new router instance
func NewRouter(defaultDNSMode bool) *Router {
	return &Router{
		staticRoutes:   make(map[string]string),
		routePatterns:  []RoutePattern{},
		defaultDNSMode: defaultDNSMode,
	}
}

// AddStaticRoute adds a static route
func (r *Router) AddStaticRoute(source, destination string) {
	r.staticRoutes[source] = destination
}

// AddRoutePattern adds a route pattern
func (r *Router) AddRoutePattern(sourcePattern, destPattern string) {
	r.routePatterns = append(r.routePatterns, RoutePattern{
		SourcePattern:      sourcePattern,
		DestinationPattern: destPattern,
	})
}

// ResolveDestination resolves the destination for a given SNI
func (r *Router) ResolveDestination(sni string) (string, error) {
	// Check static routes first (highest priority)
	if dest, ok := r.staticRoutes[sni]; ok {
		return dest, nil
	}

	// Check pattern routes
	for _, pattern := range r.routePatterns {
		if matched, dest := r.matchPattern(sni, pattern); matched {
			return dest, nil
		}
	}

	// Default to DNS lookup if enabled
	if r.defaultDNSMode {
		addrs, err := net.LookupHost(sni)
		if err != nil {
			return "", fmt.Errorf("DNS lookup failed for %s: %v", sni, err)
		}
		if len(addrs) > 0 {
			return addrs[0], nil
		}
	}

	return "", fmt.Errorf("no route found for SNI: %s", sni)
}

// matchPattern checks if an SNI matches a route pattern and returns the destination
func (r *Router) matchPattern(sni string, pattern RoutePattern) (bool, string) {
	sourceParts := strings.Split(pattern.SourcePattern, ".")
	sniParts := strings.Split(sni, ".")

	if len(sourceParts) != len(sniParts) {
		return false, ""
	}

	wildcards := make(map[int]string)

	// Check if pattern matches and collect wildcards
	for i := range sourceParts {
		if sourceParts[i] == "*" {
			wildcards[i] = sniParts[i]
		} else if sourceParts[i] != sniParts[i] {
			return false, ""
		}
	}

	// Replace wildcards in destination pattern
	destParts := strings.Split(pattern.DestinationPattern, ".")
	for i, part := range destParts {
		if part == "*" {
			if wildcard, ok := wildcards[i]; ok {
				destParts[i] = wildcard
			}
		}
	}

	return true, strings.Join(destParts, ".")
}