package fact

import (
	"net"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseEndpointV4(t *testing.T) {
	ep := IPPortValue{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 1,
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("%v", err)
	}
	key = key.PublicKey()
	ow := OnWire{
		attribute: byte(AttributeEndpointV4),
		ttl:       1,
		subject:   key[:],
		value:     ep.Bytes(),
	}
	parsed, err := Parse(&ow)
	if err != nil {
		t.Fatalf("Should have been able to parse: %v", err)
	}

	if parsed.Attribute != AttributeEndpointV4 {
		t.Errorf("Parsed attr as %v, should be %v", parsed.Attribute, AttributeEndpointV4)
	}

	if ps, ok := parsed.Subject.(*PeerSubject); !ok {
		t.Errorf("Parsed subject as a %T, not a PeerSubject", parsed.Subject)
	} else if ps.Key != key {
		t.Errorf("Parsed key as %v, should be %v", ps.Key, key)
	}

	if ippv, ok := parsed.Value.(*IPPortValue); !ok {
		t.Errorf("Parsed value as a %T, not an IPPortValue", parsed.Value)
	} else if !ippv.IP.Equal(ep.IP) || ippv.Port != ep.Port {
		t.Errorf("Parsed value as %v, should be %v", *ippv, ep)
	}
}
