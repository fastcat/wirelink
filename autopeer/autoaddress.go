// Package autopeer provides code to compute a peer's automatic IPv6-LL address
// derived from its public key.
package autopeer

import (
	"crypto/sha1"
	"net"

	"github.com/fastcat/wirelink/internal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// autoAddress computes the IPv6 link-local address that should be assigned to
// peer based on its public key
func autoAddress(key wgtypes.Key) net.IP {
	keySum := sha1.Sum(key[:])
	ip := make(net.IP, 16)
	copy(ip[0:2], []byte{0xfe, 0x80})
	copy(ip[8:], keySum[:8])
	return ip
}

// TODO: this should be done with awareness of the number of peers we're going
// to have
var aaMemo = internal.Memoize(50, 5, autoAddress)

// AutoAddress returns the IPv6 link-local address that should be assigned to
// peer based on its public key
func AutoAddress(key wgtypes.Key) net.IP {
	return aaMemo(key)
}

// AutoAddressNet returns the peer's AutoAddress with a /128 netmask
func AutoAddressNet(key wgtypes.Key) net.IPNet {
	return net.IPNet{
		IP:   AutoAddress(key),
		Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
	}
}
