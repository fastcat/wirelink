package fact

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/fastcat/wirelink/fact/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Parse tries to parse the intermediate packet format to a full data structure
func Parse(p *OnWire) (f *Fact, err error) {
	var subject types.Subject
	var value types.Value

	switch p.attribute {
	case byte(AttributeEndpointV4):
		subject, err = ParsePeerSubject(p.subject)
		if err != nil {
			return
		}
		value, err = ParseEndpointV4(p.value)
		if err != nil {
			return
		}
	case byte(AttributeEndpointV6):
		subject, err = ParsePeerSubject(p.subject)
		if err != nil {
			return
		}
		value, err = ParseEndpointV6(p.value)
		if err != nil {
			return
		}
	case byte(AttributeAllowedCidrV4):
		subject, err = ParsePeerSubject(p.subject)
		if err != nil {
			return
		}
		value, err = ParseCidrV4(p.value)
		if err != nil {
			return
		}
	case byte(AttributeAllowedCidrV6):
		subject, err = ParsePeerSubject(p.subject)
		if err != nil {
			return
		}
		value, err = ParseCidrV6(p.value)
		if err != nil {
			return
		}
	default:
		return nil, fmt.Errorf("Unrecognized attribute 0x%02x", p.attribute)
	}

	return &Fact{
		Attribute: types.Attribute(p.attribute),
		Expires:   time.Now().Add(time.Duration(p.ttl) * time.Second),
		Subject:   subject,
		Value:     value,
	}, nil
}

// ParsePeerSubject parses bytes from the wire into a peer subject object
func ParsePeerSubject(data []byte) (*types.PeerSubject, error) {
	if len(data) != wgtypes.KeyLen {
		return nil, fmt.Errorf("data len wrong for peer subject")
	}
	var key types.PeerSubject
	copy(key.Key[:], data)
	return &key, nil
}

// ParseEndpointV4 parses a bytes value as an IPv4 address and port pair
func ParseEndpointV4(data []byte) (*types.IPPortValue, error) {
	if len(data) != net.IPv4len+2 {
		return nil, fmt.Errorf("ipv4 + port should be %d bytes, not %d", net.IPv4len+2, len(data))
	}
	return &types.IPPortValue{
		IP:   net.IP(data[0:net.IPv4len]),
		Port: int(binary.BigEndian.Uint16(data[net.IPv4len:])),
	}, nil
}

// ParseEndpointV6 parses a bytes value as an IPv6 address and port pair
func ParseEndpointV6(data []byte) (*types.IPPortValue, error) {
	if len(data) != net.IPv6len+2 {
		return nil, fmt.Errorf("ipv6 + port should be 18 bytes")
	}
	return &types.IPPortValue{
		IP:   net.IP(data[0:net.IPv6len]),
		Port: int(binary.BigEndian.Uint16(data[net.IPv6len:])),
	}, nil
}

// ParseCidrV4 parses a bytes value as an IPv4 address and CIDR prefix
func ParseCidrV4(data []byte) (*types.IPNetValue, error) {
	if len(data) != net.IPv4len+1 {
		return nil, fmt.Errorf("ipv4 + prefix should be 5 bytes")
	}
	return &types.IPNetValue{
		net.IPNet{
			IP:   net.IP(data[0:net.IPv4len]),
			Mask: net.CIDRMask(int(data[net.IPv4len]), 8*net.IPv4len),
		},
	}, nil
}

// ParseCidrV6 parses a bytes value as an IPv6 address and CIDR prefix
func ParseCidrV6(data []byte) (*types.IPNetValue, error) {
	if len(data) != net.IPv6len+1 {
		return nil, fmt.Errorf("ipv6 + prefix should be 17 bytes")
	}
	return &types.IPNetValue{
		net.IPNet{
			IP:   net.IP(data[0:net.IPv6len]),
			Mask: net.CIDRMask(int(data[net.IPv6len]), 8*net.IPv6len),
		},
	}, nil
}
