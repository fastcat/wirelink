package apply

import (
	"fmt"
	"net"
	"time"

	"github.com/fastcat/wirelink/fact"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerConfigState stores state to remember peer info so we can cycle through
// configurations effectively
type PeerConfigState struct {
	lastHandshake time.Time
	lastHealthy   bool
	// the string key is really just the bytes value
	endpointLastUsed map[string]time.Time
}

// Update refreshes the PeerConfigState with new data from the wireguard device.
// NOTE: It is safe to call this on a `nil` pointer, it will return a new state
func (pcs *PeerConfigState) Update(peer *wgtypes.Peer) *PeerConfigState {
	if pcs == nil {
		pcs = &PeerConfigState{
			endpointLastUsed: make(map[string]time.Time),
		}
	}
	pcs.lastHandshake = peer.LastHandshakeTime
	newHealthy := isHealthy(pcs, peer)
	if newHealthy != pcs.lastHealthy {
		if newHealthy {
			fmt.Printf("Peer %v is now healthy\n", peer.PublicKey)
		} else {
			fmt.Printf("Peer %v is now unhealthy\n", peer.PublicKey)
		}
	}
	pcs.lastHealthy = newHealthy
	return pcs
}

// IsHealthy returns if the peer looked healthy on the last call to `Update`
func (pcs *PeerConfigState) IsHealthy() bool {
	return pcs != nil && pcs.lastHealthy
}

const endpointInterval = device.RekeyTimeout + device.KeepaliveTimeout

// TimeForNextEndpoint returns if we should try another endpoint for the peer
// (or if we should wait for the current endpoint to test out)
func (pcs *PeerConfigState) TimeForNextEndpoint() bool {
	if pcs.lastHealthy {
		return false
	}
	var timeOfLastEp time.Time
	for _, lastUsed := range pcs.endpointLastUsed {
		if lastUsed.After(timeOfLastEp) {
			timeOfLastEp = lastUsed
		}
	}

	// if it's been REKEY_TIMEOUT + KEEPALIVE since the last time we tried a new
	// ep (i.e. wireguard thinks it's time to retry the handshake), try another
	return timeOfLastEp.Add(endpointInterval).Before(time.Now())
}

// NextEndpoint recommends the next endpoint to try configuring on the peer,
// if any, based on the available facts (assumed to all be about the peer!)
// Note that this does _not_ embed the logic for whether a new endpoint _should_
// be attempted (i.e. it doesn't call `TimeForNextEndpoint` internally).
func (pcs *PeerConfigState) NextEndpoint(peerFacts []*fact.Fact) *net.UDPAddr {
	var best *fact.Fact
	// assume nothing is last used in the future
	bestLastUsed := time.Now()

	for _, pf := range peerFacts {
		switch pf.Attribute {
		case fact.AttributeEndpointV4:
			fallthrough
		case fact.AttributeEndpointV6:
			fvk := string(pf.Value.Bytes())
			lu := pcs.endpointLastUsed[fvk]
			if lu.Before(bestLastUsed) {
				best = pf
				bestLastUsed = lu
			}
		}
	}

	if best == nil {
		return nil
	}

	pcs.endpointLastUsed[string(best.Value.Bytes())] = time.Now()
	fv := best.Value.(*fact.IPPortValue)
	return &net.UDPAddr{
		IP:   fv.IP,
		Port: fv.Port,
	}
}
