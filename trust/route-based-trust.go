package trust

import (
	"bytes"
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CreateRouteBasedTrust factories a TrustEvaluator for the given set of peers,
// using the "routers are trusted" model, wherein peers are allowed to provide
// endpoint information about themselves, "routers" (peers with an AllowedIP
// whose CIDR mask is shorter than the IP length) are allowed to provide
// AllowedIPs for other peers, and nobody is allowed to provide new peers
// (peer public keys must be added by the administrator)
func CreateRouteBasedTrust(peers []wgtypes.Peer) Evaluator {
	var pps []peerWithAddr
	known := make(map[wgtypes.Key]bool)
	for i := range peers {
		a := autopeer.AutoAddress(peers[i].PublicKey)
		// need to take the address of the array element not a local iterator var here
		pps = append(pps, peerWithAddr{&peers[i], a})
		known[peers[i].PublicKey] = true
	}
	return &routeBasedTrust{pps, known}
}

type peerWithAddr struct {
	peer *wgtypes.Peer
	ip   net.IP
}

type routeBasedTrust struct {
	peers []peerWithAddr
	known map[wgtypes.Key]bool
}

// *routeBasedTrust should implement TrustEvaluator
var _ Evaluator = &routeBasedTrust{}

func (rbt *routeBasedTrust) TrustLevel(f *fact.Fact, source net.IP) Level {
	// trust peer to provide facts about itself
	ps, ok := f.Subject.(*fact.PeerSubject)
	// we only look at PeerSubject facts for this model
	if !ok {
		return Untrusted
	}
	// TODO: make a map of subjects to trusted peers to make this faster
	for _, peer := range rbt.peers {
		if source.Equal(peer.ip) {
			// peers that are allowed to route traffic are trusted to tell us about
			// any other peer, as they are inferred to control the network
			// this has to come before the peer self check, because the routers need
			// to be permitted to tell us their own AllowedIPs, not just others
			if isRouter(peer.peer) {
				return AllowedIPs
			}

			// peer is trusted to tell us its own endpoints, but not to tell us its
			// AllowedIPs
			if bytes.Equal(ps.Key[:], peer.peer.PublicKey[:]) {
				return Endpoint
			}
		}
	}

	// strangely unrecognized, suggests a router peer is forwarding packets from
	// other peers' IPv6-LL address to us... but we should have trusted that above
	// if that was happening
	return Untrusted
}

func (rbt *routeBasedTrust) IsKnown(s fact.Subject) bool {
	ps, ok := s.(*fact.PeerSubject)
	if !ok {
		return false
	}
	return rbt.known[ps.Key]
}

// isRouter considers a router to be a peer that has a global unicast allowed IP
// with a CIDR mask less than the full IP
func isRouter(peer *wgtypes.Peer) bool {
	for _, aip := range peer.AllowedIPs {
		if !aip.IP.IsGlobalUnicast() {
			continue
		}
		aipn := util.NormalizeIP(aip.IP)
		ones, size := aip.Mask.Size()
		if len(aipn)*8 == size && ones < size {
			return true
		}
	}
	return false
}