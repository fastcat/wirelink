package config

import (
	"github.com/fastcat/wirelink/trust"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peers represents a set of peer configs, with handy access methods that avoid
// boiler plate for peers that are not configured
type Peers map[wgtypes.Key]*Peer

// Name returns the name of the peer, if configured, or else its key string
func (p Peers) Name(peer wgtypes.Key) string {
	if config, ok := p[peer]; ok {
		return config.Name
	}
	return peer.String()
}

// Trust returns the configured trust level (if present and valid) or else the provided default
func (p Peers) Trust(peer wgtypes.Key, def trust.Level) trust.Level {
	if config, ok := p[peer]; ok && config.Trust != nil {
		return *config.Trust
	}
	// else fall through
	return def
}
