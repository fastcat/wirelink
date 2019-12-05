package fact

import (
	"net"
	"testing"
	"time"
)

func TestParseEndpointV4(t *testing.T) {
	ep := &IPPortValue{
		IP:   mustRandBytes(t, make([]byte, net.IPv4len)),
		Port: 1,
	}
	key := mustKey(t)

	f, p := mustSerialize(t, &Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ep,
	})

	f = mustDeserialize(t, p)

	if f.Attribute != AttributeEndpointV4 {
		t.Errorf("Parsed attr as %q, should be %q", f.Attribute, AttributeEndpointV4)
	}

	if ps, ok := f.Subject.(*PeerSubject); !ok {
		t.Errorf("Parsed subject as a %T, not a PeerSubject", f.Subject)
	} else if ps.Key != key {
		t.Errorf("Parsed key as %v, should be %v", ps.Key, key)
	}

	if ipPortVal, ok := f.Value.(*IPPortValue); !ok {
		t.Errorf("Parsed value as a %T, not an IPPortValue", f.Value)
	} else if !ipPortVal.IP.Equal(ep.IP) || ipPortVal.Port != ep.Port {
		t.Errorf("Parsed value as %v, should be %v", *ipPortVal, ep)
	}
}

func TestParseEndpointV6(t *testing.T) {
	ep := &IPPortValue{
		IP:   mustRandBytes(t, make([]byte, net.IPv6len)),
		Port: 1,
	}
	key := mustKey(t)

	f, p := mustSerialize(t, &Fact{
		Attribute: AttributeEndpointV6,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ep,
	})

	f = mustDeserialize(t, p)

	if f.Attribute != AttributeEndpointV6 {
		t.Errorf("Parsed attr as %q, should be %q", f.Attribute, AttributeEndpointV6)
	}

	if ps, ok := f.Subject.(*PeerSubject); !ok {
		t.Errorf("Parsed subject as a %T, not a PeerSubject", f.Subject)
	} else if ps.Key != key {
		t.Errorf("Parsed key as %v, should be %v", ps.Key, key)
	}

	if ipPortVal, ok := f.Value.(*IPPortValue); !ok {
		t.Errorf("Parsed value as a %T, not an IPPortValue", f.Value)
	} else if !ipPortVal.IP.Equal(ep.IP) || ipPortVal.Port != ep.Port {
		t.Errorf("Parsed value as %v, should be %v", *ipPortVal, ep)
	}
}
