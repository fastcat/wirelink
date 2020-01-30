package testutils

import (
	"net"
	"sort"
	"strings"
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

// SortIPNetSlice sorts a slice of IPNets by their string value.
// OMG want generics.
func SortIPNetSlice(slice []net.IPNet) {
	sort.Slice(slice, func(i, j int) bool {
		return strings.Compare(slice[i].String(), slice[j].String()) < 0
	})
}
