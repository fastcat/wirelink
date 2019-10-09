package apply

import (
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// isHealthy checks the state of a peer to see if connectivity to it is probably
// healthy (and thus we shouldn't change its config), or if it is unhealthy and
// we should consider updating its config to try to find a working setup.
// note that this is separate from being "Alive", which means that we have heard
// fact packet(s) from it recently
func isHealthy(state *PeerConfigState, peer *wgtypes.Peer) bool {
	// if the peer doesn't have an endpoint, it's not healthy
	if peer.Endpoint == nil {
		return false
	}
	// if the peer handshake is still valid, the peer is healthy
	// TODO: determination of the handshake validity is a bit questionable
	const HandshakeValidity = device.RekeyAfterTime +
		device.RekeyTimeout +
		device.KeepaliveTimeout +
		device.RekeyTimeoutJitterMaxMs*time.Millisecond
	if peer.LastHandshakeTime.Add(HandshakeValidity).After(time.Now()) {
		return true
	}
	// if the peer handshake has moved since we last saw it, probably healthy
	if state != nil && peer.LastHandshakeTime != state.lastHandshake {
		return true
	}
	return false
}
