// Package cmd provides the main implementation of the wirelink command line.
package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/server"
)

// WirelinkCmd represents an instance of the app command line
type WirelinkCmd struct {
	args    []string
	wgc     internal.WgClient
	Config  *config.Server
	Server  *server.LinkServer
	signals chan os.Signal
}

// New creates a new command instance using the given os.Args value
func New(args []string) *WirelinkCmd {
	ret := &WirelinkCmd{
		args: args,
	}

	return ret
}

// Init prepares the command instance
func (w *WirelinkCmd) Init(env networking.Environment) error {
	var err error
	w.wgc, err = env.NewWgClient()
	if err != nil {
		return errors.Wrapf(err, "Unable to initialize wgctrl")
	}

	flags, vcfg := config.Init(w.args)
	var configData *config.ServerData
	if configData, err = config.Parse(flags, vcfg, w.args); err != nil {
		return errors.Wrapf(err, "Unable to parse configuration")
	}
	// configData comes back nil if we ran --help or --version
	if configData == nil {
		return nil
	}

	if w.Config, err = configData.Parse(vcfg, w.wgc); err != nil {
		// TODO: this doesn't print the program name header
		flags.PrintDefaults()
		return errors.Wrapf(err, "Unable to load configuration")
	}
	if w.Config == nil {
		// config dump was requested
		return nil
	}

	w.Server, err = server.Create(env, w.wgc, w.Config)
	if err != nil {
		return errors.Wrapf(err, "Unable to create server for interface %s", w.Config.Iface)
	}

	return nil
}

// Run invokes the server
func (w *WirelinkCmd) Run() error {
	defer w.Server.Close()
	err := w.Server.Start()
	if err != nil {
		return errors.Wrapf(err, "Unable to start server for interface %s", w.Config.Iface)
	}

	w.signals = make(chan os.Signal, 5)

	w.Server.AddHandler(func(ctx context.Context) error {
		signal.Notify(w.signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
		for {
			select {
			case sig := <-w.signals:
				if sig == syscall.SIGUSR1 {
					w.Server.RequestPrint()
				} else {
					log.Info("Received signal %v, stopping", sig)
					// this will just initiate the shutdown, not block waiting for it
					w.Server.RequestStop()
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	log.Info("Server running: %s", w.Server.Describe())

	// server.Close is handled by defer above
	return w.Server.Wait()
}
