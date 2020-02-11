package server

import (
	"net"

	"github.com/fastcat/wirelink/autopeer"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// peerLookup is a map of IPv6-LL address to peer public key
type peerLookup map[[net.IPv6len]byte]wgtypes.Key

func createFromPeers(peers ...wgtypes.Peer) peerLookup {
	ret := make(peerLookup)
	ret.addPeers(peers...)
	return ret
}

func createFromKeys(peers ...wgtypes.Key) peerLookup {
	ret := make(peerLookup)
	ret.addKeys(peers...)
	return ret
}

func (pl peerLookup) addPeers(peers ...wgtypes.Peer) {
	for _, peer := range peers {
		var k [net.IPv6len]byte
		copy(k[:], autopeer.AutoAddress(peer.PublicKey).To16())
		pl[k] = peer.PublicKey
	}
}

func (pl peerLookup) addKeys(peers ...wgtypes.Key) {
	for _, peer := range peers {
		var k [net.IPv6len]byte
		copy(k[:], autopeer.AutoAddress(peer).To16())
		pl[k] = peer
	}
}

func (pl peerLookup) get(ip net.IP) (peer wgtypes.Key, ok bool) {
	var k [net.IPv6len]byte
	copy(k[:], ip.To16())
	peer, ok = pl[k]
	return
}
