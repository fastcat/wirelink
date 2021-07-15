//+build !js,!nacl,!plan9,!windows,!zos

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/fastcat/wirelink/log"
)

func (w *WirelinkCmd) addPlatformSignalHandlers() {
	w.platformSignals = make(chan os.Signal, 5)

	w.Server.AddHandler(func(ctx context.Context) error {
		signal.Notify(w.platformSignals, syscall.SIGUSR1)
		for {
			select {
			case sig := <-w.platformSignals:
				if sig == syscall.SIGUSR1 {
					w.Server.RequestPrint()
				} else {
					log.Error("Unexpected platform signal %v, ignoring", sig)
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
}
