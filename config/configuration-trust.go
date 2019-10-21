package config

import (
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/trust"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CreateTrustEvaluator maps a peer config map into an evaluator that returns the
// configured trust levels
func CreateTrustEvaluator(peers Peers) trust.Evaluator {
	return &configEvaluator{
		Peers: peers,
		// the map is lazy-built
		peerIPs: make(map[wgtypes.Key]net.IP),
	}
}

type configEvaluator struct {
	Peers
	peerIPs map[wgtypes.Key]net.IP
}

var _ trust.Evaluator = &configEvaluator{}

func (c *configEvaluator) IsKnown(subject fact.Subject) bool {
	if p, ok := subject.(*fact.PeerSubject); ok {
		if pc, ok := c.Peers[p.Key]; ok && pc.Trust != nil {
			return true
		}
	}
	return false
}

func (c *configEvaluator) TrustLevel(f *fact.Fact, source net.IP) trust.Level {
	if p, ok := f.Subject.(*fact.PeerSubject); ok {
		if pc, ok := c.Peers[p.Key]; ok && pc.Trust != nil {
			pip, ok := c.peerIPs[p.Key]
			if !ok {
				pip = autopeer.AutoAddress(p.Key)
				c.peerIPs[p.Key] = pip
			}
			if pip.Equal(source) {
				return *pc.Trust
			}
		}
	}
	return trust.Untrusted
}
