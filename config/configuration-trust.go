package config

import (
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// CreateTrustEvaluator maps a peer config map into an evaluator that returns the
// configured trust levels
func CreateTrustEvaluator(peers Peers) trust.Evaluator {
	ret := &configEvaluator{
		Peers:    peers,
		peerIPs:  make(map[wgtypes.Key]net.IP),
		ipToPeer: make(map[[net.IPv6len]byte]wgtypes.Key),
	}
	ret.updatePeerMaps()
	return ret
}

type configEvaluator struct {
	Peers
	peerIPs  map[wgtypes.Key]net.IP
	ipToPeer map[[net.IPv6len]byte]wgtypes.Key
}

var _ trust.Evaluator = &configEvaluator{}

func (c *configEvaluator) IsKnown(subject fact.Subject) bool {
	// peers are never known to the config evaluator, only trusted
	return false
}

func (c *configEvaluator) updatePeerMaps() {
	for peer := range c.Peers {
		pip := autopeer.AutoAddress(peer)
		c.peerIPs[peer] = pip
		c.ipToPeer[util.IPToBytes(pip)] = peer
	}
}

func (c *configEvaluator) TrustLevel(f *fact.Fact, source net.UDPAddr) *trust.Level {
	// we evaluate the trust level based on the _source_, not the _subject_
	// source port evaluation is left to route-based-trust
	pk, ok := c.ipToPeer[util.IPToBytes(source.IP)]
	if !ok {
		log.Info("No configured peer found for source: %v", source)
		return nil
	}
	pc, ok := c.Peers[pk]
	if !ok {
		log.Error("WAT: no configuration for recognized source %v = %v", source, pk)
		return nil
	}
	return pc.Trust
}
