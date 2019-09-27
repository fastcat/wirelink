package peerfacts

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/fastcat/wirelink/fact"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LocalFacts gets all the known facts about a local peer
func LocalFacts(peer *wgtypes.Peer, ttl time.Duration) (ret []fact.Fact, err error) {
	if peer == nil {
		return nil, fmt.Errorf("No peer")
	}
	if ttl.Seconds() < 0 || ttl.Seconds() > 255 {
		return nil, fmt.Errorf("ttl out of range")
	}

	expiration := time.Now().Add(ttl)

	// TODO: this is just a placeholder
	// ret = append(ret, fact.Fact{
	// 	Attribute: fact.AttributeUnknown,
	// 	Subject:   peer.PublicKey[:],
	// 	Value:     peer.PublicKey[:],
	// 	Expires:   expiration,
	// })

	// the endpoint is trustable if the last handshake age is less than the TTL
	if peer.Endpoint != nil && peer.LastHandshakeTime.After(time.Now().Add(-device.RekeyAfterTime)) {
		if peer.Endpoint.IP.To4() != nil {
			value := make([]byte, 6)
			copy(value, peer.Endpoint.IP.To4())
			binary.BigEndian.PutUint16(value[4:], uint16(peer.Endpoint.Port))
			ret = append(ret, fact.Fact{
				Attribute: fact.AttributeEndpointV4,
				Subject:   peer.PublicKey[:],
				Value:     value,
				Expires:   expiration,
			})
		} else if peer.Endpoint.IP.To16() != nil {
			value := make([]byte, 18)
			copy(value, peer.Endpoint.IP.To16())
			binary.BigEndian.PutUint16(value[16:], uint16(peer.Endpoint.Port))
			ret = append(ret, fact.Fact{
				Attribute: fact.AttributeEndpointV6,
				Subject:   peer.PublicKey[:],
				Value:     value,
				Expires:   expiration,
			})
		}
	}

	for _, peerIP := range peer.AllowedIPs {
		// TODO: ignore the auto-generated v6 address
		ones, _ := peerIP.Mask.Size()
		if peerIP.IP.To4() != nil {
			value := make([]byte, 5)
			copy(value, peerIP.IP.To4())
			value[4] = uint8(ones)
			ret = append(ret, fact.Fact{
				Attribute: fact.AttributeAllowedCidrV4,
				Subject:   peer.PublicKey[:],
				Value:     value,
				Expires:   expiration,
			})
		} else if peerIP.IP.To16() != nil {
			value := make([]byte, 17)
			copy(value, peerIP.IP.To16())
			value[16] = uint8(ones)
			ret = append(ret, fact.Fact{
				Attribute: fact.AttributeAllowedCidrV4,
				Subject:   peer.PublicKey[:],
				Value:     value,
				Expires:   expiration,
			})
		}
	}

	return ret, nil
}
