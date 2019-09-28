package autopeer

import (
	"crypto/sha1"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// AutoAddress returns the IPv6 link-local address that should be assigned to
// peer based on its public key
func AutoAddress(peer *wgtypes.Peer) net.IP {
	if peer == nil {
		return nil
	}

	keySum := sha1.Sum(peer.PublicKey[:])

	ip := make(net.IP, 16)
	copy(ip[0:2], []byte{0xfe, 0x80})
	copy(ip[2:], keySum[2:])
	return ip
}
