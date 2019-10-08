package apply

import (
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// isHealthy checks the state of a peer to see if connectivity to it is probably
// healthy (and thus we shouldn't change its config), or if it is unhealthy and
// we should consider updating its config to try to find a working setup
func isHealthy(state *PeerConfigState, peer *wgtypes.Peer) bool {
	// if the peer doesn't have an endpoint, it's not healthy
	if peer.Endpoint == nil {
		return false
	}
	// if the peer handshake is still valid, the peer is healthy
	if peer.LastHandshakeTime.Add(device.RekeyAfterTime).After(time.Now()) {
		return true
	}
	// if the peer handshake has moved since we last saw it, probably healthy
	if state != nil && peer.LastHandshakeTime != state.lastHandshake {
		return true
	}
	return false
}
