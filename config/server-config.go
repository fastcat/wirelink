package config

import (
	"path/filepath"

	"github.com/fastcat/wirelink/log"
)

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

// ShouldReportIface checks a given local network interface name against the config
// for whether we should tell other peers about our configuration on it
func (s *Server) ShouldReportIface(name string) bool {
	// TODO: report any broken globs found here _once_ (startup checks can't detect all broken globs)

	// Never tell peers about the wireguard interface itself
	if name == s.Iface {
		return false
	}

	// MUST NOT match any excludes
	for _, glob := range s.HideIfaces {
		if matched, err := filepath.Match(glob, name); matched && err == nil {
			log.Debug("Hiding iface '%s' because it matches exclude '%s'\n", name, glob)
			return false
		}
	}
	if len(s.ReportIfaces) == 0 {
		log.Debug("Including iface '%s' because no includes are configured", name)
		return true
	}
	// if any includes are specified, name MUST match one of them
	for _, glob := range s.ReportIfaces {
		if matched, err := filepath.Match(glob, name); matched && err == nil {
			log.Debug("Including iface '%s' because it matches include '%s'\n", name, glob)
			return true
		}
	}
	log.Debug("Hiding iface '%s' because it doesn't match any includes\n", name)
	return false
}
