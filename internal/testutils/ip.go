package testutils

import (
	"math/rand"
	"net"

	"testing"
)

// MakeIPv6 helps build IPv6 values in a similar method to how the "::" marker
// in an IPv6 literal works
func MakeIPv6(left, right []byte) net.IP {
	ret := make([]byte, net.IPv6len)
	copy(ret, left)
	copy(ret[net.IPv6len-len(right):], right)
	return ret
}

// MakeIPv6Net uses MakeIPv6 to create a net.IPNet with the built IP and the given
// CIDR mask length
func MakeIPv6Net(left, right []byte, ones int) net.IPNet {
	return net.IPNet{
		IP:   MakeIPv6(left, right),
		Mask: net.CIDRMask(ones, 8*net.IPv6len),
	}
}

// MakeIPv4Net creates a net.IPNet with the given address and CIDR mask length
func MakeIPv4Net(a, b, c, d byte, ones int) net.IPNet {
	return net.IPNet{
		IP:   net.IPv4(a, b, c, d).To4(),
		Mask: net.CIDRMask(ones, 8*net.IPv4len),
	}
}

// RandIPNet generates a random IPNet of the given size, and with optional fixed left/right bytes,
// and with the given CIDR prefix length
func RandIPNet(t *testing.T, size int, left, right []byte, ones int) net.IPNet {
	ipBytes := MustRandBytes(t, make([]byte, size))
	if len(left) > 0 {
		copy(ipBytes, left)
	}
	if len(right) > 0 {
		copy(ipBytes[net.IPv6len-len(right):], right)
	}
	return net.IPNet{
		IP:   ipBytes,
		Mask: net.CIDRMask(ones, 8*size),
	}
}

// RandUDP4Addr generates a random IPv4 UDP address for test purposes
func RandUDP4Addr(t *testing.T) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   MustRandBytes(t, make([]byte, net.IPv4len)),
		Port: rand.Intn(65535),
	}
}

// RandUDP6Addr generates a random IPv6 UDP address for test purposes
func RandUDP6Addr(t *testing.T) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   MustRandBytes(t, make([]byte, net.IPv6len)),
		Port: rand.Intn(65535),
	}
}

// ContainsIPNet runs a predicate across a net.IPNet slice and returns if any match was found
func ContainsIPNet(addrs []net.IPNet, predicate func(net.IPNet) bool) bool {
	for _, addr := range addrs {
		if predicate(addr) {
			return true
		}
	}
	return false
}
