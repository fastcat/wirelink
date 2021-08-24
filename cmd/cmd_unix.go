//go:build !js && !nacl && !plan9 && !windows && !zos
// +build !js,!nacl,!plan9,!windows,!zos

package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

func (w *WirelinkCmd) addPlatformSignalHandlers() {
	signal.Notify(w.signals, syscall.SIGUSR1)
}

func (w *WirelinkCmd) handlePlatformSignal(sig os.Signal) bool {
	if sig == syscall.SIGUSR1 {
		w.Server.RequestPrint()
		return true
	}
	return false
}

func (w *WirelinkCmd) sendPrintRequestSignal() {
	w.signals <- syscall.SIGUSR1
}

const platformIFNAMSIZ = syscall.IFNAMSIZ
