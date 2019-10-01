package fact

import (
	"fmt"
	"time"

	"github.com/fastcat/wirelink/fact/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Parse tries to parse the intermediate packet format to a full data structure
func Parse(p *OnWire) (f *Fact, err error) {
	if f == nil {
		return nil, fmt.Errorf("packet is nil")
	}

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

func ParseEndpointV4(data []byte) (*types.IPPortValue, error) {
	return nil, fmt.Errorf("not implemented")
}
func ParseEndpointV6(data []byte) (*types.IPPortValue, error) {
	return nil, fmt.Errorf("not implemented")
}
func ParseCidrV4(data []byte) (*types.IPPortValue, error) {
	return nil, fmt.Errorf("not implemented")
}
func ParseCidrV6(data []byte) (*types.IPPortValue, error) {
	return nil, fmt.Errorf("not implemented")
}
