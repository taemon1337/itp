package router

// Route represents a routing configuration
type Route struct {
	Source      string
	SourcePath  string // Path prefix for matching requests
	Destination string
	DestPath    string // Path prefix for destination, if empty source path is stripped
	PreserveTLS bool   // If true, use original destination hostname for TLS verification
}

// RoutePattern represents a pattern-based routing configuration
type RoutePattern struct {
	SourcePattern      string
	DestinationPattern string
}
