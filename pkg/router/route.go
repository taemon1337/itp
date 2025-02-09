package router

// Route represents a routing configuration
type Route struct {
	Source      string
	SourcePath  string // Path prefix for matching requests
	Destination string
	DestPath    string // Path prefix for destination, if empty source path is stripped
}

// RoutePattern represents a pattern-based routing configuration
type RoutePattern struct {
	SourcePattern      string
	DestinationPattern string
}
