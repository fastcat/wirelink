package apply

import (
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TODO: the timing constants here should be moved somewhere more general

// HealthHysteresisBandaid is an extra delay to add before considering a peer
// unhealthy, based on as-yet undiagnosed observations of handshakes not
// refreshing as often as documentation seems to suggest they should
const HealthHysteresisBandaid = 30 * time.Second

// HandshakeValidityBase is the base amount of time we think a handshake should be valid for,
// without accounting for tolerances
const HandshakeValidityBase = device.RekeyAfterTime +
	device.RekeyTimeout +
	device.KeepaliveTimeout +
	device.RekeyTimeoutJitterMaxMs*time.Millisecond

// HandshakeValidity is how long we thing a handshake should be valid for,
// including tolerances
const HandshakeValidity = HandshakeValidityBase + HealthHysteresisBandaid

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
	if peer.LastHandshakeTime.Add(HandshakeValidity).After(time.Now()) {
		return true
	}
	// if the peer handshake has moved since we last saw it, probably healthy
	if state != nil && peer.LastHandshakeTime != state.lastHandshake {
		return true
	}
	return false
}

// IsHandshakeHealthy returns whether the handshake looks recent enough that the
// peer is likely to be in communication.
func IsHandshakeHealthy(lastHandshake time.Time) bool {
	return lastHandshake.Add(HandshakeValidity).After(time.Now())
}
