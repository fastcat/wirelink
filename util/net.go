package util

import (
	"errors"
	"net"
	"strings"
)

// NetClosingErrorString is the voodoo string returned when you try to use a
// Close()d network connection, because https://github.com/golang/go/issues/4373
const NetClosingErrorString = "use of closed network connection"

// IsNetClosing checks err and its Unwrap chain for NetClosingErrorString
func IsNetClosing(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), NetClosingErrorString) {
		return true
	}
	return IsNetClosing(errors.Unwrap(err))
}

// UDPEqualIPPort checks if to UDPAddrs are equal in terms of their IP and Port
// fields, but ignoring any Zone value
func UDPEqualIPPort(a, b *net.UDPAddr) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && a.Port == b.Port
}
