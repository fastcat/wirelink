package trust

import (
	"bytes"
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/fact/types"
	"github.com/fastcat/wirelink/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func CreateRouteBasedTrust(peers []wgtypes.Peer) TrustEvaluator {
	var pps []peerWithAddr
	for i, _ := range peers {
		a := autopeer.AutoAddress(peers[i].PublicKey)
		// need to take the address of the array element not a local iterator var here
		pps = append(pps, peerWithAddr{&peers[i], a})
	}
	return &routeBasedTrust{pps}
}

type peerWithAddr struct {
	peer *wgtypes.Peer
	ip   net.IP
}

type routeBasedTrust struct {
	peers []peerWithAddr
}

// *routeBasedTrust should implement TrustEvaluator
var _ TrustEvaluator = &routeBasedTrust{}

func (rbt *routeBasedTrust) IsTrusted(fact *fact.Fact, source net.IP) bool {
	// trust peer to provide facts about itself
	ps, ok := fact.Subject.(*types.PeerSubject)
	// we only look at PeerSubject facts for this model
	if !ok {
		return false
	}
	// TODO: make a map of subjects to trusted peers to make this faster
	for _, peer := range rbt.peers {
		if source.Equal(peer.ip) {
			// peer is trusted to tell us about itself
			if bytes.Equal(ps.Key[:], peer.peer.PublicKey[:]) {
				return true
			}
			// peers that are allowed to route traffic are trusted to tell us about
			// any other peer, as they are inferred to control the network
			if isRouter(peer.peer) {
				return true
			}
		}
	}
	return false
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
