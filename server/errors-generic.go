//+build !linux

package server

import (
	"os"
	"syscall"
)

func isSysErrUnreachable(err *os.SyscallError) bool {
	// EDESTADDRREQ and ENETUNREACH happen when we have a bad address for
	// talking to a peer, whether when inside the tunnel or for the tunnel
	// endpoint. EPERM and ENOKEY happens if we have no handshake. Except
	// ENOKEY is linux specific, so it's not checked here.
	return err.Err == syscall.EDESTADDRREQ ||
		err.Err == syscall.ENETUNREACH ||
		err.Err == syscall.EPERM
}
