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

// IsGloballyRoutable checks if an IP address looks routable across the internet
// or not. It will return false for any IP that is not a Global Unicast address,
// and also for certain special reserved subnets that are used within site-level
// domains but are not meant to be routed on the internet.
func IsGloballyRoutable(ip net.IP) bool {
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		// ignore the CG-NAT subnet 100.64.0.0/10 (https://tools.ietf.org/html/rfc6598)
		if ip4[0] == 0x64 && ip4[1] >= 0x40 && ip4[1] <= 0x7f {
			return false
		}
		// TODO: more ranges?
	}
	if ip6 := ip.To16(); ip6 != nil {
		// fc00::/7 ~ ipv6 equivalent of 10/8-ish
		if ip6[0] == 0xfc || ip6[0] == 0xfd {
			return false
		}
	}

	// TODO: more ipv6 reserved ranges
	// https://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
	return true
}
