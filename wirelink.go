package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/server"

	"golang.zx2c4.com/wireguard/wgctrl"
)

func main() {
	err := realMain()
	// don't print on error just because help was requested
	if err != nil && err != pflag.ErrHelp {
		fmt.Fprintf(os.Stderr, "Fatal error: %v", err)
		defer os.Exit(1)
	}
}

func realMain() error {
	wgc, err := wgctrl.New()
	if err != nil {
		return errors.Wrapf(err, "Unable to initialize wgctrl")
	}

	flags, vcfg := config.Init()
	var configData *config.ServerData
	if configData, err = config.Parse(flags, vcfg); err != nil {
		return errors.Wrapf(err, "Failed to load config")
	}
	// configData comes back nil if we ran --help or --version
	if configData == nil {
		return nil
	}

	var serverConfig *config.Server
	if serverConfig, err = configData.Parse(vcfg, wgc); err != nil {
		// TODO: this doesn't print the program name header
		flags.PrintDefaults()
		return errors.Wrapf(err, "Unable to load configuration")
	}
	if serverConfig == nil {
		// config dump was requested
		return nil
	}

	server, err := server.Create(wgc, serverConfig)
	if err != nil {
		return errors.Wrapf(err, "Unable to create server for interface %s", serverConfig.Iface)
	}
	defer server.Close()
	err = server.Start()
	if err != nil {
		return errors.Wrapf(err, "Unable to start server for interface %s", serverConfig.Iface)
	}

	log.Info("Server running: %s", server.Describe())

	server.AddHandler(func(ctx context.Context) error {
		signals := make(chan os.Signal, 5)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
		for {
			select {
			case sig := <-signals:
				if sig == syscall.SIGUSR1 {
					server.RequestPrint()
				} else {
					log.Info("Received signal %v, stopping", sig)
					// this will just initiate the shutdown, not block waiting for it
					server.RequestStop()
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	// server.Close is handled by defer above
	return server.Wait()
}
