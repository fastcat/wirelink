// Package facts provides helper code for generating facts for use in unit tests.
package facts

import (
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EndpointValue wraps a UDPAddr in an IPPortValue
func EndpointValue(ep *net.UDPAddr) *fact.IPPortValue {
	return &fact.IPPortValue{
		IP:   util.NormalizeIP(ep.IP),
		Port: ep.Port,
	}
}

// EndpointFact wraps a UDPAddr in a Fact, with just the Attribute and Value filled
func EndpointFact(ep *net.UDPAddr) *fact.Fact {
	value := EndpointValue(ep)
	ret := &fact.Fact{
		Attribute: fact.AttributeEndpointV4,
		Value:     value,
	}
	if len(value.IP) == net.IPv6len {
		ret.Attribute = fact.AttributeEndpointV6
	}
	return ret
}

// EndpointFactFull wraps a UDPAddr in a Fact, with all fields filled
func EndpointFactFull(ep *net.UDPAddr, peer *wgtypes.Key, expires time.Time) *fact.Fact {
	value := EndpointValue(ep)
	ret := &fact.Fact{
		Attribute: fact.AttributeEndpointV4,
		Subject:   &fact.PeerSubject{Key: *peer},
		Expires:   expires,
		Value:     value,
	}
	if len(value.IP) == net.IPv6len {
		ret.Attribute = fact.AttributeEndpointV6
	}
	return ret
}

// AllowedIPFactFull wraps an IPNet in a Fact, with all fields filled
func AllowedIPFactFull(aip net.IPNet, peer *wgtypes.Key, expires time.Time) *fact.Fact {
	ret := &fact.Fact{
		Attribute: fact.AttributeAllowedCidrV4,
		Subject:   &fact.PeerSubject{Key: *peer},
		Expires:   expires,
		Value:     &fact.IPNetValue{IPNet: aip},
	}
	if len(aip.IP) == net.IPv6len {
		ret.Attribute = fact.AttributeAllowedCidrV6
	}
	return ret
}

// MemberFactFull returns a membership fact for the given peer
func MemberFactFull(peer *wgtypes.Key, expires time.Time) *fact.Fact {
	return &fact.Fact{
		Attribute: fact.AttributeMember,
		Subject:   &fact.PeerSubject{Key: *peer},
		Expires:   expires,
		Value:     &fact.EmptyValue{},
	}
}

// AliveFact generates an alive fact for the peer, with a zero boot ID
func AliveFact(peer *wgtypes.Key, expires time.Time) *fact.Fact {
	return &fact.Fact{
		Attribute: fact.AttributeAlive,
		Subject:   &fact.PeerSubject{Key: *peer},
		Expires:   expires,
		Value:     &fact.UUIDValue{},
	}
}

// AliveFactFull generates an alive fact for the peer, with the given boot ID
func AliveFactFull(peer *wgtypes.Key, expires time.Time, bootID uuid.UUID) *fact.Fact {
	return &fact.Fact{
		Attribute: fact.AttributeAlive,
		Subject:   &fact.PeerSubject{Key: *peer},
		Expires:   expires,
		Value:     &fact.UUIDValue{UUID: bootID},
	}
}
