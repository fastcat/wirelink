package apply

import (
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerConfigState stores state to remember peer info so we can cycle through
// configurations effectively
type PeerConfigState struct {
	lastHandshake time.Time
	lastHealthy   bool
	lastAlive     bool
	lastBootID    *uuid.UUID
	aliveSince    time.Time
	aliveUntil    time.Time
	// the string key is really just the bytes value
	endpointLastUsed map[string]time.Time
	metadata         map[fact.MemberAttribute]string
}

// EnsureNotNil returns either its receiver if not nil, or else a new object suitable to be its receiver
func (pcs *PeerConfigState) EnsureNotNil() *PeerConfigState {
	if pcs == nil {
		pcs = &PeerConfigState{
			endpointLastUsed: make(map[string]time.Time),
		}
	}
	return pcs
}

// Clone makes a deep clone of the receiver
func (pcs *PeerConfigState) Clone() *PeerConfigState {
	if pcs == nil {
		return nil
	}

	ret := *pcs
	if ret.lastBootID != nil {
		copy := *ret.lastBootID
		ret.lastBootID = &copy
	}
	if pcs.endpointLastUsed != nil {
		ret.endpointLastUsed = make(map[string]time.Time, len(pcs.endpointLastUsed))
		for k, v := range pcs.endpointLastUsed {
			ret.endpointLastUsed[k] = v
		}
	}
	return &ret
}

// Update returns a cloned PeerConfigState with new data from the wireguard device.
// NOTE: It is safe to call this on a `nil` pointer, it will return a new state.
// TODO: give this access to the `peerKnowledgeSet` instead of passing in the alive state
func (pcs *PeerConfigState) Update(
	peer *wgtypes.Peer,
	configName string,
	newAlive bool,
	aliveUntil time.Time,
	bootID *uuid.UUID,
	now time.Time,
	facts []*fact.Fact,
	quiet bool,
) *PeerConfigState {
	pcs = pcs.EnsureNotNil()
	// clone before updates to prevent data races
	pcs = pcs.Clone()
	pcs.lastHandshake = peer.LastHandshakeTime
	newHealthy := isHealthy(pcs, peer)
	var bootChanged, firstBoot bool
	if bootID != nil {
		bootChanged = pcs.lastBootID != nil && *bootID != *pcs.lastBootID
		firstBoot = pcs.lastBootID == nil
	}
	changed := newHealthy != pcs.lastHealthy || newAlive != pcs.lastAlive || bootChanged
	if changed && newHealthy && newAlive {
		pcs.aliveSince = now
	}
	pcs.lastHealthy = newHealthy
	pcs.lastAlive = newAlive
	if newAlive {
		pcs.aliveUntil = aliveUntil
	} else {
		pcs.aliveUntil = time.Time{}
	}
	// don't forget the last bootID if we temporarily lose the peer, only reset it when it really changes
	if bootID != nil {
		pcs.lastBootID = bootID
	}
	pcs.metadata = mergeMetadata(facts)
	name := configName
	if len(name) == 0 {
		name = pcs.metadata[fact.MemberName]
		if len(name) == 0 {
			name = peer.PublicKey.String()
		}
	}
	if !quiet {
		// don't log the first boot as a reboot
		if bootChanged && !firstBoot {
			log.Info("Peer %s is now %s (rebooted)", name, pcs.Describe(now))
		} else if changed {
			log.Info("Peer %s is now %s", name, pcs.Describe(now))
		}
	}
	return pcs
}

func mergeMetadata(facts []*fact.Fact) map[fact.MemberAttribute]string {
	metadata := map[fact.MemberAttribute]string{}
	for _, f := range facts {
		if f.Attribute != fact.AttributeMemberMetadata {
			continue
		}
		mv := f.Value.(*fact.MemberMetadata)
		mv.ForEach(func(a fact.MemberAttribute, v string) {
			// TODO: don't overwrite full string with empty string
			metadata[a] = v
		})
	}
	if len(metadata) == 0 {
		metadata = nil
	}
	return metadata
}

// Describe gives a textual summary of the state.
// Note that this is not done as String() because it doesn't represent the whole object.
func (pcs *PeerConfigState) Describe(now time.Time) string {
	if pcs == nil {
		return "???"
	}
	hsAge := now.Sub(pcs.lastHandshake).Truncate(time.Millisecond)
	aliveFor := pcs.aliveUntil.Sub(now).Truncate(time.Millisecond)
	if pcs.lastHealthy {
		if pcs.lastAlive {
			return fmt.Sprintf("%s (%v -> %v)", "healthy and alive", hsAge, aliveFor)
		}
		return fmt.Sprintf("%s (%s)", "healthy but not alive", hsAge)
	} else if pcs.lastAlive {
		return fmt.Sprintf("%s (%v -> %v)", "unhealthy but alive?", hsAge, aliveFor)
	} else {
		return fmt.Sprintf("%s (%s)", "unhealthy", hsAge)
	}
}

// IsHealthy returns if the peer looked healthy on the last call to `Update`
func (pcs *PeerConfigState) IsHealthy() bool {
	return pcs != nil && pcs.lastHealthy
}

// IsAlive returns if the peer looked alive on the last call to `Update`.
// note that a peer can be alive but unhealthy!
func (pcs *PeerConfigState) IsAlive() bool {
	return pcs != nil && pcs.lastAlive
}

// AliveSince gives the time since which the peer has been healthy and alive,
// or a _very_ far future value if it is not healthy and alive.
func (pcs *PeerConfigState) AliveSince() time.Time {
	if pcs != nil && pcs.lastHealthy && pcs.lastAlive {
		return pcs.aliveSince
	}
	return util.TimeMax()
}

// AliveUntil gives the time until which the peer will be considered alive,
// or zero value if it is not healthy or alive.
func (pcs *PeerConfigState) AliveUntil() time.Time {
	if pcs != nil && pcs.lastHealthy && pcs.lastAlive {
		return pcs.aliveUntil
	}
	return time.Time{}
}

// TryGetMetadata fetches the value of the given member metadata attribute,
// if it is known.
func (pcs *PeerConfigState) TryGetMetadata(attr fact.MemberAttribute) (string, bool) {
	if pcs == nil || pcs.metadata == nil {
		return "", false
	}
	val, ok := pcs.metadata[attr]
	return val, ok
}

// IsBasic checks if there is a MemberIsBasic attribute present and its value
// is truthy. If no attribute is present, it returns false.
func (pcs *PeerConfigState) IsBasic() bool {
	value, ok := pcs.TryGetMetadata(fact.MemberIsBasic)
	if !ok || len(value) == 0 {
		return false
	}
	return value[0] != 0
}

const endpointInterval = device.RekeyTimeout + device.KeepaliveTimeout

// TimeForNextEndpoint returns if we should try another endpoint for the peer
// (or if we should wait for the current endpoint to test out)
func (pcs *PeerConfigState) TimeForNextEndpoint() bool {
	if pcs == nil {
		// if we know nothing about the peer, we don't have an endpoint configured,
		// and so we should definitely try to make one
		return true
	}

	if pcs.lastHealthy {
		return false
	}
	var timeOfLastEp time.Time
	for _, lastUsed := range pcs.endpointLastUsed {
		if lastUsed.After(timeOfLastEp) {
			timeOfLastEp = lastUsed
		}
	}

	// if we've never tried any endpoints, definitely should try one now
	if len(pcs.endpointLastUsed) == 0 {
		return true
	}

	// if it's been REKEY_TIMEOUT + KEEPALIVE since the last time we tried a new
	// ep (i.e. wireguard thinks it's time to retry the handshake), try another
	return timeOfLastEp.Add(endpointInterval).Before(time.Now())
}

// NextEndpoint recommends the next endpoint to try configuring on the peer,
// if any, based on the available facts (assumed to all be about the peer!)
// Note that this does _not_ embed the logic for whether a new endpoint _should_
// be attempted (i.e. it doesn't call `TimeForNextEndpoint` internally).
func (pcs *PeerConfigState) NextEndpoint(
	peerName string,
	peerFacts []*fact.Fact,
	now time.Time,
	filter func(*fact.Fact) bool,
) *net.UDPAddr {
	var best *fact.Fact
	// assume nothing is last used in the future
	bestLastUsed := now

	for _, pf := range peerFacts {
		switch pf.Attribute {
		case fact.AttributeEndpointV4, fact.AttributeEndpointV6:
			if filter != nil && !filter(pf) {
				log.Debug("skipping peer %s endpoint %s", peerName, pf.Value)
				continue
			}
			// this logic relies on the zero value of a Time being very far in the past
			lu := pcs.endpointLastUsed[string(util.MustBytes(pf.Value.MarshalBinary()))]
			if lu.Before(bestLastUsed) {
				best = pf
				bestLastUsed = lu
			}
		}
	}

	if best == nil {
		return nil
	}

	pcs.endpointLastUsed[string(util.MustBytes(best.Value.MarshalBinary()))] = now
	fv := best.Value.(*fact.IPPortValue)
	return &net.UDPAddr{
		IP:   fv.IP,
		Port: fv.Port,
	}
}
