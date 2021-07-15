//+build js nacl plan9 windows zos

package cmd

func (w *WirelinkCmd) addPlatformSignalHandlers() {
	// no SIGUSR1 support here, so this is a no-op
}
