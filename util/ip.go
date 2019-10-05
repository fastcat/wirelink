package util

import (
	"bytes"
	"net"
)

func NormalizeIP(ip net.IP) net.IP {
	n := ip.To4()
	if n == nil {
		n = ip.To16()
	}
	return n
}

func IsIPv6LLMatch(expected net.IP, actual *net.IPNet, local bool) bool {
	expectedOnes := 8 * net.IPv6len
	if local {
		expectedOnes = 4 * net.IPv6len
	}
	ones, bits := actual.Mask.Size()
	return ones == expectedOnes && bits == 8*net.IPv6len && bytes.Equal(expected, actual.IP)
}
