//+build js nacl plan9 windows zos

package cmd

import "os"

// no SIGUSR1 support here, so these are no-ops

func (w *WirelinkCmd) addPlatformSignalHandlers() {
}

func (w *WirelinkCmd) handlePlatformSignal(os.Signal) bool {
	return false
}

func (w *WirelinkCmd) sendPrintRequestSignal() {
}

// who knows if this is correct, just copying the linux value here
const platformIFNAMSIZ = 16
