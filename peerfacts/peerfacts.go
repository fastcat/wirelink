package peerfacts

import (
	"fmt"
	"net"
	"time"

	"github.com/fastcat/wirelink/autopeer"
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

	addAttr := func(attr fact.Attribute, value fact.Value) {
		fact := fact.Fact{
			Attribute: attr,
			Subject:   PeerSubject{peer.PublicKey},
			Value:     value,
			Expires:   expiration,
		}
		ret = append(ret, fact)
	}

	// the endpoint is trustable if the last handshake age is less than the TTL
	if peer.Endpoint != nil && peer.LastHandshakeTime.After(time.Now().Add(-device.RekeyAfterTime)) {
		if peer.Endpoint.IP.To4() != nil {
			addAttr(fact.AttributeEndpointV4, IPValue{peer.Endpoint.IP})
		} else if peer.Endpoint.IP.To16() != nil {
			addAttr(fact.AttributeEndpointV6, IPValue{peer.Endpoint.IP})
		}
	}

	autoAddress := autopeer.AutoAddress(peer)
	if autoAddress != nil {
		addAttr(fact.AttributeAllowedCidrV6, IPNetValue{net.IPNet{
			IP:   autoAddress,
			Mask: net.CIDRMask(128, 128),
		}})
	}

	for _, peerIP := range peer.AllowedIPs {
		// TODO: ignore the auto-generated v6 address
		if peerIP.IP.To4() != nil {
			addAttr(fact.AttributeAllowedCidrV4, IPNetValue{peerIP})
		} else if peerIP.IP.To16() != nil {
			// ignore link-local addresses, particularly the auto-generated v6 one
			if peerIP.IP[0] == 0xfe && peerIP.IP[1] == 0x80 {
				continue
			}
			addAttr(fact.AttributeAllowedCidrV6, IPNetValue{peerIP})
		}
	}

	return ret, nil
}

// PeerSubject is a subject that is a peer identified via its public key
type PeerSubject struct {
	wgtypes.Key
}

// Bytes gives the binary representation of a peer's public key
func (s PeerSubject) Bytes() []byte {
	return s.Key[:]
}

// PeerSubject must implement Subject
var _ fact.Subject = PeerSubject{}

// IPValue represents some IP address as an Attribute of a Subject
type IPValue struct {
	net.IP
}

// IPValue must implement Value
var _ fact.Value = IPValue{}

// Bytes returns the normalized binary representation
func (ip IPValue) Bytes() []byte {
	normalized := ip.To4()
	if normalized == nil {
		normalized = ip.To16()
	}
	return normalized
}

// IPNetValue represents some IP+Mask as an Attribute of a Subject
type IPNetValue struct {
	net.IPNet
}

// IPNetValue must implement Value
var _ fact.Value = IPNetValue{}

// Bytes gives the binary representation of the ip and cidr prefix
func (ipn IPNetValue) Bytes() []byte {
	ipnorm := ipn.IP.To4()
	if ipnorm == nil {
		ipnorm = ipn.IP.To16()
	}
	ones, _ := ipn.Mask.Size()
	ret := make([]byte, len(ipnorm), len(ipnorm)+1)
	copy(ret, ipnorm)
	ret = append(ret, uint8(ones))
	return ret
}

func (ipn IPNetValue) String() string {
	return ipn.IPNet.String()
}
