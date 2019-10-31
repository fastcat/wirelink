package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// ServerData represents the raw data from the config for the server,
// before it is cleaned up into a `Server` config object.
type ServerData struct {
	Iface  string
	Port   int
	Router string
	Peers  []PeerData

	ReportIfaces []string
	HideIfaces   []string

	Dump bool

	// this prop is here for compat, but is ignored because it's how we find the
	// config file, so the config file can't use it to point at a different config
	configPath string `mapstructure:"config-path"`
}

// Parse converts the raw configuration data into a ready to use server config.
func (s *ServerData) Parse(vcfg *viper.Viper, wgc *wgctrl.Client) (ret *Server, err error) {
	ret = new(Server)
	ret.Iface = s.Iface
	ret.Port = s.Port

	// TODO: replace strings bool with real bool for router mode
	if s.Dump {
		all := vcfg.AllSettings()
		// don't dump the dump setting
		delete(all, DumpConfigFlag)
		// fixup the router flag
		if rv, ok := all[RouterFlag]; ok && rv != RouterAuto {
			if rv, err = strconv.ParseBool(rv.(string)); err != nil {
				return nil, errors.Wrapf(err, "Invalid value for 'router'")
			}
			all[RouterFlag] = rv
		}
		dump, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to serialize settings to JSON")
		}
		// marshal output never has the trailing newline
		dump = append(dump, '\n')
		_, err = os.Stdout.Write(dump)
		return nil, err
	}

	// replace "auto" with the real value
	if s.Router == RouterAuto {
		// try to auto-detect router mode
		// if there are no other routers ... then we're probably a router
		// this is pretty weak, better would be to check if our IP is within some other peer's AllowedIPs
		dev, err := wgc.Device(s.Iface)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to open wireguard device for interface %s", s.Iface)
		}

		otherRouters := false
		for _, p := range dev.Peers {
			if trust.IsRouter(&p) {
				otherRouters = true
				break
			}
		}

		ret.IsRouter = !otherRouters
	} else {
		// force it to be a real bool for later
		ret.IsRouter, err = strconv.ParseBool(s.Router)
		if err != nil {
			return nil, errors.Wrapf(err, "Invalid value for 'router'")
		}
	}

	// validate all the globs
	for _, glob := range s.ReportIfaces {
		if _, err = filepath.Match(glob, ""); err != nil {
			return nil, errors.Wrapf(err, "Bad glob in ReportIfaces config: '%s'", glob)
		}
	}
	for _, glob := range s.HideIfaces {
		if _, err = filepath.Match(glob, ""); err != nil {
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
		log.Info("Configured peer '%s': %s", key, &peerConf)
	}

	return
}
