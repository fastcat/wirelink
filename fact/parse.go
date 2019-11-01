package fact

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// UUID package doesn't provide this constant for us
const uuidLen = 16

// prove to ourselves it's correct
var _ = uuid.UUID([uuidLen]byte{})

// Parse tries to parse the intermediate packet format to a full data structure
func Parse(p *OnWire) (f *Fact, err error) {
	var subject *PeerSubject
	var value Value

	switch p.attribute {
	case byte(AttributeUnknown):
		// Legacy ping packet
		subject, err = ParsePeerSubject(p.subject)
		if err != nil {
			return
		}
		if len(p.value) != 0 {
			return nil, fmt.Errorf("No-attribute packets must have empty value, not %d", len(p.value))
		}
		value = EmptyValue{}

	case byte(AttributeAlive):
		// Modern ping packet with boot id embedded in value
		subject, err = ParsePeerSubject(p.subject)
		if err != nil {
			return
		}
		if len(p.value) != uuidLen {
			return nil, fmt.Errorf("Alive packets must have UUID-sized value, not %d", len(p.value))
		}
		value, err = ParseUUID(p.value)
		if err != nil {
			return
		}

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
	case byte(AttributeSignedGroup):
		subject, err = ParsePeerSubject(p.subject)
		if err != nil {
			return
		}
		value, err = ParseSignedGroupValue(p.value)
		if err != nil {
			return
		}
	default:
		return nil, fmt.Errorf("Unrecognized attribute 0x%02x", p.attribute)
	}

	return &Fact{
		Attribute: Attribute(p.attribute),
		Expires:   time.Now().Add(time.Duration(p.ttl) * time.Second),
		Subject:   subject,
		Value:     value,
	}, nil
}

// ParseUUID parses bytes from the wire into a uuid value object
func ParseUUID(data []byte) (*UUIDValue, error) {
	if len(data) != uuidLen {
		return nil, fmt.Errorf("data len wrong for uuid value")
	}
	var val UUIDValue
	copy(val.UUID[:], data)
	return &val, nil
}

// ParsePeerSubject parses bytes from the wire into a peer subject object
func ParsePeerSubject(data []byte) (*PeerSubject, error) {
	if len(data) != wgtypes.KeyLen {
		return nil, fmt.Errorf("data len wrong for peer subject")
	}
	var key PeerSubject
	copy(key.Key[:], data)
	return &key, nil
}

// ParseEndpointV4 parses a bytes value as an IPv4 address and port pair
func ParseEndpointV4(data []byte) (*IPPortValue, error) {
	if len(data) != net.IPv4len+2 {
		return nil, fmt.Errorf("ipv4 + port should be %d bytes, not %d", net.IPv4len+2, len(data))
	}
	return &IPPortValue{
		IP:   net.IP(data[0:net.IPv4len]),
		Port: int(binary.BigEndian.Uint16(data[net.IPv4len:])),
	}, nil
}

// ParseEndpointV6 parses a bytes value as an IPv6 address and port pair
func ParseEndpointV6(data []byte) (*IPPortValue, error) {
	if len(data) != net.IPv6len+2 {
		return nil, fmt.Errorf("ipv6 + port should be 18 bytes")
	}
	return &IPPortValue{
		IP:   net.IP(data[0:net.IPv6len]),
		Port: int(binary.BigEndian.Uint16(data[net.IPv6len:])),
	}, nil
}

// ParseCidrV4 parses a bytes value as an IPv4 address and CIDR prefix
func ParseCidrV4(data []byte) (*IPNetValue, error) {
	if len(data) != net.IPv4len+1 {
		return nil, fmt.Errorf("ipv4 + prefix should be 5 bytes")
	}
	return &IPNetValue{
		IPNet: net.IPNet{
			IP:   net.IP(data[0:net.IPv4len]),
			Mask: net.CIDRMask(int(data[net.IPv4len]), 8*net.IPv4len),
		},
	}, nil
}

// ParseCidrV6 parses a bytes value as an IPv6 address and CIDR prefix
func ParseCidrV6(data []byte) (*IPNetValue, error) {
	if len(data) != net.IPv6len+1 {
		return nil, fmt.Errorf("ipv6 + prefix should be 17 bytes")
	}
	return &IPNetValue{
		IPNet: net.IPNet{
			IP:   net.IP(data[0:net.IPv6len]),
			Mask: net.CIDRMask(int(data[net.IPv6len]), 8*net.IPv6len),
		},
	}, nil
}

// ParseSignedGroupValue parses a bytes value as a Nonce, Tag, and inner data array
func ParseSignedGroupValue(data []byte) (*SignedGroupValue, error) {
	// smallest possible inner fact is 4 bytes (assuming empty subject and value)
	if len(data) < sgvOverhead+4 {
		return nil, fmt.Errorf("SignedGroupValue should be at least %d+4 bytes long", sgvOverhead)
	}
	var ret SignedGroupValue
	copy(ret.Nonce[:], data[0:len(ret.Nonce)])
	copy(ret.Tag[:], data[len(ret.Nonce):len(ret.Nonce)+len(ret.Tag)])
	// deserialize copied the packet buffer so we can just reference the rest of it as-is
	ret.InnerBytes = data[len(ret.Nonce)+len(ret.Tag):]

	return &ret, nil
}

// ParseInner parses the inner bytes of a SignedGroupValue into facts.
// Validating the signature must be done separately, and should be done before
// calling this method.
func (sgv *SignedGroupValue) ParseInner() (ret []*Fact, err error) {
	o := 0
	for b := sgv.InnerBytes; len(b) > 0; {
		var w *OnWire
		var rem []byte
		w, rem, err = deserializeSlice(b)
		if err != nil {
			err = errors.Wrapf(err, "Unable to deserialize from SignedGroupValue at %d", o)
			return
		}
		var f *Fact
		f, err = Parse(w)
		if err != nil {
			err = errors.Wrapf(err, "Unable to parse from SignedGroupValue at %d", o)
			return
		}
		// Don't allow nested signed groups for now
		if f.Attribute == AttributeSignedGroup {
			err = fmt.Errorf("SignedGroups must not be nested")
			return
		}
		ret = append(ret, f)
		o += len(b) - len(rem)
		b = rem
	}
	return
}
