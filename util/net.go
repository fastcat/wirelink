package util

import (
	"net"
	"sort"
	"strings"

	"github.com/pkg/errors"
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

// SortIPNetSlice sorts a slice of IPNets by their string value, returning the
// (modified in place) slice.
// OMG want generics.
func SortIPNetSlice(slice []net.IPNet) []net.IPNet {
	sort.Slice(slice, func(i, j int) bool {
		return strings.Compare(slice[i].String(), slice[j].String()) < 0
	})
	return slice
}

// CloneIPNet makes a deep copy of the given value
func CloneIPNet(ipn net.IPNet) net.IPNet {
	var ret net.IPNet
	ret.IP = make(net.IP, len(ipn.IP))
	copy(ret.IP, ipn.IP)
	ret.Mask = make(net.IPMask, len(ipn.Mask))
	copy(ret.Mask, ipn.Mask)
	return ret
}

// CloneUDPAddr makes a deep copy of the given address
func CloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}

	ret := &net.UDPAddr{
		Port: addr.Port,
		Zone: addr.Zone,
	}
	ret.IP = make(net.IP, len(addr.IP))
	copy(ret.IP, addr.IP)
	return ret
}
