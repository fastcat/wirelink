package peerfacts

import (
	"fmt"
	"time"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/fact/types"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LocalFacts gets all the known facts about a local peer
func LocalFacts(peer *wgtypes.Peer, ttl time.Duration) (ret []*fact.Fact, err error) {
	if ttl.Seconds() < 0 || ttl.Seconds() > 255 {
		return nil, fmt.Errorf("ttl out of range")
	}

	expiration := time.Now().Add(ttl)

	addAttr := func(attr types.Attribute, value types.Value) {
		ret = append(ret, &fact.Fact{
			Attribute: attr,
			Subject:   types.PeerSubject{Key: peer.PublicKey},
			Value:     value,
			Expires:   expiration,
		})
	}

	// the endpoint is trustable if the last handshake age is less than the TTL
	if peer.Endpoint != nil && peer.LastHandshakeTime.After(time.Now().Add(-device.RekeyAfterTime)) {
		if peer.Endpoint.IP.To4() != nil {
			addAttr(fact.AttributeEndpointV4, types.IPPortValue{IP: peer.Endpoint.IP, Port: peer.Endpoint.Port})
		} else if peer.Endpoint.IP.To16() != nil {
			addAttr(fact.AttributeEndpointV6, types.IPPortValue{IP: peer.Endpoint.IP, Port: peer.Endpoint.Port})
		}
	}

	// don't publish the autoaddress, everyone can figure that out on their own,
	// and must already know it in order to receive the data anyways

	for _, peerIP := range peer.AllowedIPs {
		// TODO: ignore the auto-generated v6 address
		if peerIP.IP.To4() != nil {
			addAttr(fact.AttributeAllowedCidrV4, types.IPNetValue{IPNet: peerIP})
		} else if peerIP.IP.To16() != nil {
			// ignore link-local addresses, particularly the auto-generated v6 one
			if peerIP.IP[0] == 0xfe && peerIP.IP[1] == 0x80 {
				continue
			}
			addAttr(fact.AttributeAllowedCidrV6, types.IPNetValue{IPNet: peerIP})
		}
	}

	return ret, nil
}
