package config

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/log"
)

const (
	// RouterFlag is the name of the flag to set router mode
	RouterFlag = "router"
	// IfaceFlag is the name of the flag to set the wireguard interface to use
	IfaceFlag = "iface"
	// DumpConfigFlag is the name of the flag to request config dumping
	DumpConfigFlag = "dump"
	// VersionFlag is the name of the flag to request printing the program version
	VersionFlag = "version"
	// HelpFlag is the name of the flag to request printing program usage
	HelpFlag = "help"
	// ConfigPathFlag is the name of the setting for the config file base path
	ConfigPathFlag = "config-path"
	// DebugFlag enables debug logging
	DebugFlag = "debug"
	// ChattyFlag is the name of the setting to enable chatty mode
	ChattyFlag = "chatty"
)

func programName(args []string) string {
	base := path.Base(args[0])
	ext := path.Ext(base)
	if len(ext) > 0 {
		base = base[:len(base)-len(ext)]
	}
	return base
}

func programInfo(args []string) string {
	return fmt.Sprintf("%s (%s)", programName(args), internal.Version)
}

// Init sets up the config flags and other parsing setup
func Init(args []string) (flags *pflag.FlagSet, vcfg *viper.Viper) {
	flags = pflag.NewFlagSet(programInfo(args), pflag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage of %s:\n", programInfo(args))
		flags.PrintDefaults()
	}
	vcfg = viper.New()

	// need this for `AllSettings` to type things that come from the environment correctly
	// this also requires explicitly specifying defaults for everything, not just relying on the flag default
	vcfg.SetTypeByDefaultValue(true)

	flags.Bool(RouterFlag, false, "Is the local device a router (bool, omit for autodetect)")

	vcfg.SetDefault(IfaceFlag, "wg0")
	flags.StringP(IfaceFlag, "i", "wg0", "Interface on which to operate")

	vcfg.SetDefault(DumpConfigFlag, false)
	flags.Bool(DumpConfigFlag, false, "Dump configuration instead of running")

	vcfg.SetDefault(VersionFlag, false)
	flags.Bool(VersionFlag, false, "Print program version")

	vcfg.SetDefault(HelpFlag, false)
	flags.BoolP(HelpFlag, "h", false, "Print program usage")

	vcfg.SetDefault(ConfigPathFlag, "/etc/wireguard")
	// no flag for config-path for now, only env

	vcfg.SetDefault(DebugFlag, false)
	flags.BoolP(DebugFlag, "d", false, "Enable debug logging output")

	vcfg.SetDefault(ChattyFlag, false)
	flags.Bool(ChattyFlag, false, "Enable chatty mode (for fact exchangers)")

	err := vcfg.BindPFlags(flags)
	// this should never happen, flags are constant
	if err != nil {
		panic(err)
	}
	vcfg.SetEnvPrefix(programName(args))
	vcfg.AutomaticEnv()
	// hard to set env vars with hyphens, bash doesn't like it
	vcfg.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	return flags, vcfg
}

// Parse reads flags and configs
func Parse(flags *pflag.FlagSet, vcfg *viper.Viper, args []string) (ret *ServerData, err error) {
	err = flags.Parse(args[1:])
	if err != nil {
		flags.Usage()
		return ret, err
	}
	// activate debug logging immediately
	if debug, _ := flags.GetBool(DebugFlag); debug {
		log.SetDebug(true)
	}

	// handle --version and --help specially
	if help, _ := flags.GetBool(HelpFlag); help {
		// if help is requested explicitly, don't send it to stderr
		flags.SetOutput(os.Stdout)
		flags.Usage()
		return nil, nil
	}
	if version, _ := flags.GetBool(VersionFlag); version {
		_, err = fmt.Printf("%s\n", programInfo(args))
		return nil, err
	}

	// setup the config file -- can't do this until after we've parsed the iface flag
	// in theory the config file can override the iface, but ... that would be bad
	// this needs to happen _before_ the `router` processing since the config may set that
	vcfg.SetConfigName(fmt.Sprintf("%s.%s", programName(args), vcfg.GetString(IfaceFlag)))
	// this is perversely recursive
	vcfg.AddConfigPath(vcfg.GetString(ConfigPathFlag))

	err = vcfg.ReadInConfig()
	if err != nil {
		// config file not found is harmless
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("unable to read config file: %w", err)
		}
	}

	// load peer configurations
	ret = new(ServerData)
	if err = vcfg.UnmarshalExact(ret); err != nil {
		flags.Usage()
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}

	// viper/pflags doesn't have the concept of an optional setting that isn't set
	// have to do some mucking to fake it
	if !vcfg.IsSet(RouterFlag) {
		ret.Router = nil
	}

	return ret, err
}
