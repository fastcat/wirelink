package apply

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const endpointBytesLen = net.IPv6len + 2

type endpointAsBytes [endpointBytesLen]byte

// PeerConfigState stores state to remember peer info so we can cycle through
// configurations effectively
type PeerConfigState struct {
	lastHandshake    time.Time
	lastHealthy      bool
	endpointLastUsed map[endpointAsBytes]time.Time
}

// Update refreshes the PeerConfigState with new data from the wireguard device.
// NOTE: It is safe to call this on a `nil` pointer, it will return a new state
func (pcs *PeerConfigState) Update(peer *wgtypes.Peer) *PeerConfigState {
	if pcs == nil {
		pcs = &PeerConfigState{
			endpointLastUsed: make(map[endpointAsBytes]time.Time),
		}
	}
	pcs.lastHandshake = peer.LastHandshakeTime
	pcs.lastHealthy = isHealthy(pcs, peer)
	return pcs
}

// IsHealthy returns if the peer looked healthy on the last call to `Update`
func (pcs *PeerConfigState) IsHealthy() bool {
	return pcs != nil && pcs.lastHealthy
}

// TimeForNextEndpoint returns if we should try another endpoint for the peer
// (or if we should wait for the current endpoint to test out)
func (pcs *PeerConfigState) TimeForNextEndpoint() bool {
	if pcs.lastHealthy {
		return false
	}
	// if it's been REKEY_TIMEOUT + KEEPALIVE since the last handshake (i.e.
	// wireguard thinks it's time to retry the handshake), try another endpoint
	return pcs.lastHandshake.
		Add(device.RekeyTimeout).
		Add(device.KeepaliveTimeout).
		Before(time.Now())
}
