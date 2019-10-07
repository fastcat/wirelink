package server

import (
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// peerLookup is a map of IPv6-LL address to peer public key
type peerLookup map[[16]byte]wgtypes.Key

func createPeerLookup(peers []wgtypes.Peer) peerLookup {
	ret := make(peerLookup)
	ret.addPeers(peers)
	return ret
}

func (pl peerLookup) addPeers(peers []wgtypes.Peer) {
	for _, peer := range peers {
		var k [16]byte
		copy(k[:], autopeer.AutoAddress(peer.PublicKey).To16())
		pl[k] = peer.PublicKey
	}
}

func (pl peerLookup) get(ip net.IP) (peer wgtypes.Key, ok bool) {
	var k [16]byte
	copy(k[:], ip.To16())
	peer, ok = pl[k]
	return
}
