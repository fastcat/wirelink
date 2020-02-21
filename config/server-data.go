package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/spf13/viper"

	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/log"
)

// ServerData represents the raw data from the config for the server,
// before it is cleaned up into a `Server` config object.
type ServerData struct {
	Iface  string
	Port   int
	Router *bool
	Chatty bool

	Peers []PeerData

	ReportIfaces []string
	HideIfaces   []string

	Debug   bool
	Dump    bool
	Help    bool
	Version bool

	// this prop is here for compat, but is ignored because it's how we find the
	// config file, so the config file can't use it to point at a different config
	configPath string `mapstructure:"config-path"`
}

// Parse converts the raw configuration data into a ready to use server config.
func (s *ServerData) Parse(vcfg *viper.Viper, wgc internal.WgClient) (ret *Server, err error) {
	// apply this right away, but only as an enable
	// once debug is on, leave it on (esp. for tests)
	if s.Debug {
		log.SetDebug(s.Debug)
	}

	ret = new(Server)
	//TODO: validate Iface is not empty
	ret.Iface = s.Iface
	ret.Port = s.Port
	ret.Chatty = s.Chatty

	// validate all the globs
	// have to pass a non-empty candidate string to actually get error checking
	// even that is dodgy as a failed match before the bad part of the pattern
	// will prevent the error from being reported
	// passing the glob to itself works for many common cases
	for _, glob := range s.ReportIfaces {
		if _, err = filepath.Match(glob, glob); err != nil {
			return nil, errors.Wrapf(err, "Bad glob in ReportIfaces config: '%s'", glob)
		}
	}
	for _, glob := range s.HideIfaces {
		if _, err = filepath.Match(glob, glob); err != nil {
			return nil, errors.Wrapf(err, "Bad glob in HideIfaces config: '%s'", glob)
		}
	}
	ret.ReportIfaces = s.ReportIfaces
	ret.HideIfaces = s.HideIfaces

	ret.Peers = make(Peers)
	for _, peerDatum := range s.Peers {
		key, peerConf, err := peerDatum.Parse()
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse peer config from %+v", peerDatum)
		}
		ret.Peers[key] = &peerConf
		// skip this log if we're in config dump mode, so that the output is _just_ the JSON
		if !s.Dump {
			log.Info("Configured peer '%s': %s", key, &peerConf)
		}
	}

	ret.Debug = s.Debug

	if s.Router == nil {
		// autodetect if we should be in router mode or not
		ret.AutoDetectRouter = true
		// can't auto-detect yet until we start the server. OK to assume we are not a router for now.
	} else {
		ret.AutoDetectRouter = false
		ret.IsRouterNow = *s.Router
	}

	if s.Dump {
		all := vcfg.AllSettings()
		// don't dump cli mode args
		delete(all, DumpConfigFlag)
		delete(all, VersionFlag)
		delete(all, HelpFlag)
		// have to fix the Router setting again
		if s.Router == nil {
			delete(all, RouterFlag)
		}
		// this still leaves a few settings in the output that wouldn't _normally_
		// be there, and which might not work fully in a config file:
		// `config-path`, `debug`, and `iface` at least.
		// however the point here is more to dump the effective config than to
		// regurgitate the input
		dump, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to serialize settings to JSON")
		}
		// marshal output never has the trailing newline
		dump = append(dump, '\n')
		_, err = os.Stdout.Write(dump)
		return nil, err
	}

	return
}
