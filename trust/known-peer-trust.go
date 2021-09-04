package trust

import (
	"bytes"
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CreateKnownPeerTrust creates a trust Evaluator for the given set of peers,
// where a known peer is allowed to tell us Endpoint facts, but not register new
// peers.
func CreateKnownPeerTrust(peers []wgtypes.Peer) Evaluator {
	// TODO: share some of the data structures here with RouteBasedTrust
	ret := knownPeerTrust{
		peersByIP:  make(map[[net.IPv6len]byte]*peerWithAddr),
		peersByKey: make(map[wgtypes.Key]*peerWithAddr),
	}
	for i := range peers {
		a := autopeer.AutoAddress(peers[i].PublicKey)
		// need to take the address of the array element not a local var
		pwa := peerWithAddr{
			peer: &peers[i],
			ip:   a,
		}
		ret.peersByIP[util.IPToBytes(a)] = &pwa
		ret.peersByKey[peers[i].PublicKey] = &pwa
	}
	return &ret
}

type knownPeerTrust struct {
	peersByIP  map[[net.IPv6len]byte]*peerWithAddr
	peersByKey map[wgtypes.Key]*peerWithAddr
}

// *routeBasedTrust should implement TrustEvaluator
var _ Evaluator = &routeBasedTrust{}

func (rbt *knownPeerTrust) TrustLevel(f *fact.Fact, source net.UDPAddr) *Level {
	ps, ok := f.Subject.(*fact.PeerSubject)
	// we only look at PeerSubject facts for this model
	if !ok {
		return nil
	}

	peer, ok := rbt.peersByIP[util.IPToBytes(source.IP)]
	if !ok {
		// strangely unrecognized, suggests a router peer is forwarding packets from
		// other peers' IPv6-LL address to us
		return nil
	}

	// peer is trusted to tell us its own endpoints, but not to tell us its
	// AllowedIPs
	if bytes.Equal(ps.Key[:], peer.peer.PublicKey[:]) {
		ret := Endpoint
		return &ret
	}

	// actually, known peers are allowed to tell us endpoints for _any_ known peer
	ret := Endpoint
	return &ret
}

// IsKnown returns whether the subject is known to us, i.e.  whether the peer
// is locally known
func (rbt *knownPeerTrust) IsKnown(s fact.Subject) bool {
	ps, ok := s.(*fact.PeerSubject)
	// we only look at PeerSubject facts for this model
	if !ok {
		return false
	}
	_, ok = rbt.peersByKey[ps.Key]
	return ok
}
