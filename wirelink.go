package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/server"
	"github.com/fastcat/wirelink/trust"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	err := realMain()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		defer os.Exit(1)
	}
}

func realMain() error {
	wgc, err := wgctrl.New()
	if err != nil {
		return errors.Wrapf(err, "Unable to initialize wgctrl")
	}

	flags := pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)
	vcfg := viper.New()
	const RouterFlag = "router"
	const RouterAuto = "auto"
	const IfaceFlag = "iface"
	const DumpConfigFlag = "dump"
	const ConfigPathFlag = "config-path"
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

	err = flags.Parse(os.Args[1:])
	if err != nil {
		// TODO: this causes the error to be printed twice: once by flags and once by `main`
		// TODO: this also causes an error to be printed & returned when run with `--help`
		return err
	}

	iface := vcfg.GetString(IfaceFlag)

	// setup the config file -- can't do this until after we've parsed the iface flag
	// in theory the config file can override the iface, but ... that would be bad
	// this needs to happen _before_ the `router` processing since the config may set that
	vcfg.SetConfigName(fmt.Sprintf("wirelink.%s", iface))
	// this is perversely recursive
	vcfg.AddConfigPath(vcfg.GetString(ConfigPathFlag))

	err = vcfg.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, harmless
		} else {
			return errors.Wrap(err, "Unable to read config file")
		}
	}

	// replace anything other than "auto" with a boolean
	routerStrVal := vcfg.GetString(RouterFlag)
	if routerStrVal != RouterAuto {
		// force it to be a real bool for later
		routerBoolVal, err := strconv.ParseBool(routerStrVal)
		if err != nil {
			// TODO: this doesn't print the program name header
			flags.PrintDefaults()
			return errors.Wrapf(err, "Invalid value for 'router'")
		}
		vcfg.Set(RouterFlag, routerBoolVal)
	}

	// dump settings _before_ we replace auto with a boolean
	if vcfg.GetBool(DumpConfigFlag) {
		all := vcfg.AllSettings()
		// don't dump the dump setting
		delete(all, DumpConfigFlag)
		dump, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return errors.Wrapf(err, "Unable to serialize settings to JSON")
		}
		// marshal output never has the trailing newline
		dump = append(dump, '\n')
		_, err = os.Stdout.Write(dump)
		return err
	}

	// load peer configuations
	var peerData []config.PeerData
	// TODO: can't combine UnmarshalExact with UnmarshalKey, so we can't error on bad keys here
	if err = vcfg.UnmarshalKey("peers", &peerData); err != nil {
		return errors.Wrapf(err, "Unable to parse config for peers")
	}
	peerConfigs := make(config.Peers)
	for _, peerDatum := range peerData {
		key, peerConf, err := peerDatum.Parse()
		if err != nil {
			return errors.Wrapf(err, "Cannot parse peer config from %+v", peerDatum)
		}
		peerConfigs[key] = &peerConf
		log.Info("Configured peer '%s': %s", key, &peerConf)
	}

	// replace "auto" with the real value
	if routerStrVal == RouterAuto {
		// try to auto-detect router mode
		// if there are no other routers ... then we're probably a router
		// this is pretty weak, better would be to check if our IP is within some other peer's AllowedIPs
		dev, err := wgc.Device(iface)
		if err != nil {
			return errors.Wrapf(err, "Unable to open wireguard device for interface %s", iface)
		}

		otherRouters := false
		for _, p := range dev.Peers {
			if trust.IsRouter(&p) {
				otherRouters = true
				break
			}
		}

		vcfg.Set(RouterFlag, !otherRouters)
	}

	isRouter := vcfg.GetBool(RouterFlag)
	serverConfig := config.Server{
		Iface:    iface,
		IsRouter: isRouter,
		Peers:    peerConfigs,
	}
	server, err := server.Create(wgc, &serverConfig)
	if err != nil {
		return errors.Wrapf(err, "Unable to initialize server for interface %s", iface)
	}
	defer server.Close()

	nodeTypeDesc := "leaf"
	if isRouter {
		nodeTypeDesc = "router"
	}
	log.Info("Server running on {%s} [%v]:%v (%s)", iface, server.Address(), server.Port(), nodeTypeDesc)

	sigs := make(chan os.Signal, 5)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)

	onStopped := server.OnStopped()

DONE:
	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGUSR1 {
				server.RequestPrint()
			} else {
				log.Info("Received signal %v, stopping", sig)
				// request stop in the background, we'll catch the channel message when it's complete
				go server.Stop()
			}
		case exitOk := <-onStopped:
			if !exitOk {
				log.Error("Server hit an error")
				defer os.Exit(1)
			} else {
				log.Info("Server stopped")
				server.RequestPrint()
			}
			break DONE
		}
	}

	// server.Close is handled by defer above
	return nil
}
