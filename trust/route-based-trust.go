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

func CreateRouteBasedTrust(peers []*wgtypes.Peer) TrustEvaluator {
	var pps []peerWithAddr
	for _, p := range peers {
		a := autopeer.AutoAddress(p.PublicKey)
		pps = append(pps, peerWithAddr{p, a})
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
	ps, ok := fact.Subject.(types.PeerSubject)
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
			// peers that have an allowed ip with a cidr mask less than the length
			// arre trusted to tell us about any other peer -- they are inferred to
			// be routers that control the network
			for _, aip := range peer.peer.AllowedIPs {
				if !aip.IP.IsGlobalUnicast() {
					continue
				}
				aipn := util.NormalizeIP(aip.IP)
				ones, size := aip.Mask.Size()
				if len(aipn) == ones && len(aipn) == size {
					return true
				}
			}
		}
	}
	return false
}
