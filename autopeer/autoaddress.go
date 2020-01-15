package autopeer

import (
	"crypto/sha1"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AutoAddress returns the IPv6 link-local address that should be assigned to
// peer based on its public key
func AutoAddress(key wgtypes.Key) net.IP {
	keySum := sha1.Sum(key[:])
	ip := make(net.IP, 16)
	copy(ip[0:2], []byte{0xfe, 0x80})
	copy(ip[8:], keySum[:8])
	return ip
}

// AutoAddressNet returns the peer's AutoAddress with a /128 netmask
func AutoAddressNet(key wgtypes.Key) net.IPNet {
	return net.IPNet{
		IP:   AutoAddress(key),
		Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
	}
}
