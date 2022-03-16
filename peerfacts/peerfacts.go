package peerfacts

import (
	"fmt"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/fact"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LocalFacts gets all the known facts about a local peer
func LocalFacts(
	peer *wgtypes.Peer,
	ttl time.Duration,
	trustLocalAIPs bool,
	trustLocalMembership bool,
	now time.Time,
) (ret []*fact.Fact, err error) {
	// NOTE: we can represent more than 255 seconds at the protocol level now,
	// but longer than that is probably a bad idea for the time being
	if ttl.Seconds() < 0 || ttl.Seconds() > 255 {
		return nil, fmt.Errorf("ttl out of range")
	}

	expiration := now.Add(ttl)

	addAttr := func(attr fact.Attribute, value fact.Value) {
		ret = append(ret, &fact.Fact{
			Attribute: attr,
			Subject:   &fact.PeerSubject{Key: peer.PublicKey},
			Value:     value,
			Expires:   expiration,
		})
	}

	// the endpoint is trustable if the last handshake age is less than the TTL
	if peer.Endpoint != nil && peer.LastHandshakeTime.After(now.Add(-apply.HandshakeValidity)) {
		if peer.Endpoint.IP.To4() != nil {
			addAttr(fact.AttributeEndpointV4, &fact.IPPortValue{IP: peer.Endpoint.IP, Port: peer.Endpoint.Port})
		} else if peer.Endpoint.IP.To16() != nil {
			addAttr(fact.AttributeEndpointV6, &fact.IPPortValue{IP: peer.Endpoint.IP, Port: peer.Endpoint.Port})
		}
	}

	// don't publish the autoaddress, everyone can figure that out on their own,
	// and must already know it in order to receive the data anyways

	if trustLocalAIPs {
		for _, peerIP := range peer.AllowedIPs {
			if peerIP.IP.To4() != nil {
				addAttr(fact.AttributeAllowedCidrV4, &fact.IPNetValue{IPNet: peerIP})
			} else if peerIP.IP.To16() != nil {
				// ignore link-local addresses, particularly the auto-generated v6 one
				if peerIP.IP[0] == 0xfe && peerIP.IP[1] == 0x80 {
					continue
				}
				addAttr(fact.AttributeAllowedCidrV6, &fact.IPNetValue{IPNet: peerIP})
			}
		}
	}

	if trustLocalMembership {
		// always use MemberMetadata even if we don't have any metadata
		addAttr(fact.AttributeMemberMetadata, &fact.MemberMetadata{})
	}

	return ret, nil
}
