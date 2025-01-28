package router

// Route represents a routing configuration
type Route struct {
	Source      string
	Destination string
}

// RoutePattern represents a pattern-based routing configuration
type RoutePattern struct {
	SourcePattern      string
	DestinationPattern string
}
