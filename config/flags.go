package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// DumpConfigFlag is the name of the flag to request config dumping
const DumpConfigFlag = "dump"

// RouterFlag is the name of the flag to set router mode
const RouterFlag = "router"

// IfaceFlag is the name of the flag to set the wireguard interface to use
const IfaceFlag = "iface"

// ConfigPathFlag is the name of the setting for the config file base path
const ConfigPathFlag = "config-path"

// RouterAuto is the magic string for the Router config entry to request auto-detection
const RouterAuto = "auto"

// Init sets up the config flags and other parsing setup
func Init() (flags *pflag.FlagSet, vcfg *viper.Viper) {
	flags = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)
	vcfg = viper.New()

	// viper.IsSet is useless when flags are in play, so we have to make this a string we parse ourselves
	vcfg.SetDefault(RouterFlag, RouterAuto)
	flags.String(RouterFlag, RouterAuto, "Is the local device a router (bool or \"auto\")")
	vcfg.SetDefault(IfaceFlag, "wg0")
	flags.String("iface", "wg0", "Interface on which to operate")
	vcfg.SetDefault(DumpConfigFlag, false)
	flags.Bool(DumpConfigFlag, false, "Dump configuration instead of running")
	vcfg.SetDefault(ConfigPathFlag, "/etc/wireguard")
	// no flag for this one for now, only env

	vcfg.BindPFlags(flags)
	vcfg.SetEnvPrefix("wirelink")
	vcfg.AutomaticEnv()
	// hard to set env vars with hyphens, bash doesn't like it
	vcfg.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	return
}

// Parse reads flags and configs
func Parse(flags *pflag.FlagSet, vcfg *viper.Viper) (ret *ServerData, err error) {
	err = flags.Parse(os.Args[1:])
	if err != nil {
		// TODO: this causes the error to be printed twice: once by flags and once by `main`
		// TODO: this also causes an error to be printed & returned when run with `--help`
		return
	}

	// setup the config file -- can't do this until after we've parsed the iface flag
	// in theory the config file can override the iface, but ... that would be bad
	// this needs to happen _before_ the `router` processing since the config may set that
	vcfg.SetConfigName(fmt.Sprintf("wirelink.%s", vcfg.GetString(IfaceFlag)))
	// this is perversely recursive
	vcfg.AddConfigPath(vcfg.GetString(ConfigPathFlag))

	err = vcfg.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, harmless
		} else {
			return nil, errors.Wrap(err, "Unable to read config file")
		}
	}

	// load peer configuations
	ret = new(ServerData)
	// TODO: can't use UnmarshalExact here because we have lots of keys we don't care about for now
	if err = vcfg.Unmarshal(ret); err != nil {
		// TODO: this doesn't print the program name header
		flags.PrintDefaults()
		return nil, errors.Wrapf(err, "Unable to parse config")
	}

	return
}
