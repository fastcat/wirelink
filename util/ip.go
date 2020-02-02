package util

import (
	"net"
)

// NormalizeIP returns a version of the given ip normalized to its underlying
// family, instead of the "always in IPv6 container" format that is often used,
// so IPv4 values will have a length of 4 and IPv6 ones a length of 16
func NormalizeIP(ip net.IP) net.IP {
	n := ip.To4()
	if n == nil {
		n = ip.To16()
	}
	return n
}

// IsIPv6LLMatch checks if a given expected IPv6 address matches an actual
// address + mask, checking if the mask is of the expected form.
// The mask is expected to be /128 if local is false, or /64 if it is true
func IsIPv6LLMatch(expected net.IP, actual *net.IPNet, local bool) bool {
	expectedOnes := 8 * net.IPv6len
	if local {
		expectedOnes = 4 * net.IPv6len
	}
	ones, bits := actual.Mask.Size()
	return ones == expectedOnes && bits == 8*net.IPv6len && expected.Equal(actual.IP)
}

// IPToBytes returns the given IP normalized to a 16 byte array,
// suitable for use as a map key among other things
func IPToBytes(ip net.IP) (ret [net.IPv6len]byte) {
	ip = ip.To16()
	copy(ret[:], ip)
	return
}
