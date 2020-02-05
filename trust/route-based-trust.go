package trust

import (
	"bytes"
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/detect"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CreateRouteBasedTrust factories a TrustEvaluator for the given set of peers,
// using the "routers are trusted" model, wherein peers are allowed to provide
// endpoint information, "routers" (peers with an AllowedIP whose CIDR mask is
// shorter than the IP length) are allowed to provide AllowedIPs for other
// peers, and nobody is allowed to provide new peers (peer public keys must be
// added by the administrator)
func CreateRouteBasedTrust(peers []wgtypes.Peer) Evaluator {
	ret := routeBasedTrust{
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

type peerWithAddr struct {
	peer *wgtypes.Peer
	ip   net.IP
}

type routeBasedTrust struct {
	peersByIP  map[[net.IPv6len]byte]*peerWithAddr
	peersByKey map[wgtypes.Key]*peerWithAddr
}

// *routeBasedTrust should implement TrustEvaluator
var _ Evaluator = &routeBasedTrust{}

func (rbt *routeBasedTrust) TrustLevel(f *fact.Fact, source net.UDPAddr) *Level {
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

	// peers that are allowed to route traffic are trusted to tell us about
	// any other peer, as they are inferred to control the network this has
	// to come before the peer self check, because the routers need to be
	// permitted to tell us their own AllowedIPs, not just others.
	// re-evaluating this each time instead of caching it once at startup is
	// intentional as peer AIPs that drive this can change
	if detect.IsPeerRouter(peer.peer) {
		ret := Membership
		return &ret
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
func (rbt *routeBasedTrust) IsKnown(s fact.Subject) bool {
	ps, ok := s.(*fact.PeerSubject)
	// we only look at PeerSubject facts for this model
	if !ok {
		return false
	}
	_, ok = rbt.peersByKey[ps.Key]
	return ok
}
