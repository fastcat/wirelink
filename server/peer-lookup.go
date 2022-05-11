package server

import (
	"net"
	"sync"

	"github.com/fastcat/wirelink/autopeer"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type (
	ipBytes    = [net.IPv6len]byte
	peerLookup struct {
		mu sync.RWMutex
		ip map[wgtypes.Key]net.IP
		p  map[ipBytes]wgtypes.Key
		// TODO: LRU trimming
	}
)

func newPeerLookup() *peerLookup {
	return &peerLookup{
		ip: map[wgtypes.Key]net.IP{},
		p:  map[ipBytes]wgtypes.Key{},
	}
}

func (pl *peerLookup) GetPeer(ip net.IP) (peer wgtypes.Key, ok bool) {
	var k ipBytes
	copy(k[:], ip.To16())
	pl.mu.RLock()
	peer, ok = pl.p[k]
	pl.mu.RUnlock()
	return
}

// func (pl *peerLookup) GetIP(peer wgtypes.Key) net.IP {
// 	pl.mu.RLock()
// 	if ip, ok := pl.ip[peer]; ok {
// 		pl.mu.RUnlock()
// 		return ip
// 	}
// 	pl.mu.RUnlock()
// 	pl.mu.Lock()
// 	ip := autopeer.AutoAddress(peer)
// 	var k ipBytes
// 	copy(k[:], ip.To16())
// 	pl.ip[peer] = ip
// 	pl.p[k] = peer
// 	return ip
// }

func (pl *peerLookup) addPeers(peers ...wgtypes.Peer) {
	pl.mu.Lock()
	for _, p := range peers {
		if _, ok := pl.ip[p.PublicKey]; !ok {
			ip := autopeer.AutoAddress(p.PublicKey)
			var k ipBytes
			copy(k[:], ip.To16())
			pl.ip[p.PublicKey] = ip
			pl.p[k] = p.PublicKey
		}
	}
	pl.mu.Unlock()
}

func (pl *peerLookup) addKeys(peers ...wgtypes.Key) {
	pl.mu.Lock()
	for _, p := range peers {
		if _, ok := pl.ip[p]; !ok {
			ip := autopeer.AutoAddress(p)
			var k ipBytes
			copy(k[:], ip.To16())
			pl.ip[p] = ip
			pl.p[k] = p
		}
	}
	pl.mu.Unlock()
}
