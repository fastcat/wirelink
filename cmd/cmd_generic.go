//go:build js || nacl || plan9 || windows || zos
// +build js nacl plan9 windows zos

package cmd

import (
	"os"
	"os/signal"
)

func (w *WirelinkCmd) addSignalHandlers() {
	signal.Notify(w.signals, os.Interrupt)
}

func (w *WirelinkCmd) handlePlatformSignal(os.Signal) bool {
	return false
}

func (w *WirelinkCmd) sendPrintRequestSignal() {
}

// who knows if this is correct, just copying the linux value here
const platformIFNAMSIZ = 16
