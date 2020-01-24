package config

// Server describes the configuration for the server, after parsing from various sources
type Server struct {
	Iface  string
	Port   int
	Chatty bool

	AutoDetectRouter bool
	IsRouterNow      bool

	ReportIfaces []string
	HideIfaces   []string

	Peers Peers

	Debug bool
}
