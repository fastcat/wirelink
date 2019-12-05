package fact

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.Equal(t, AttributeEndpointV4, f.Attribute)

	require.IsType(t, &PeerSubject{}, f.Subject)
	assert.Equal(t, key, f.Subject.(*PeerSubject).Key)

	require.IsType(t, &IPPortValue{}, f.Value)
	assert.Equal(t, ep.IP, f.Value.(*IPPortValue).IP)
	assert.Equal(t, ep.Port, f.Value.(*IPPortValue).Port)
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

	assert.Equal(t, AttributeEndpointV6, f.Attribute)

	require.IsType(t, &PeerSubject{}, f.Subject)
	assert.Equal(t, key, f.Subject.(*PeerSubject).Key)

	require.IsType(t, &IPPortValue{}, f.Value)
	assert.Equal(t, ep.IP, f.Value.(*IPPortValue).IP)
	assert.Equal(t, ep.Port, f.Value.(*IPPortValue).Port)
}

func TestParseCidrV4(t *testing.T) {
	ipn := &IPNetValue{
		IPNet: net.IPNet{
			IP:   mustRandBytes(t, make([]byte, net.IPv4len)),
			Mask: net.CIDRMask(rand.Intn(8*net.IPv4len), 8*net.IPv4len),
		},
	}
	key := mustKey(t)

	f, p := mustSerialize(t, &Fact{
		Attribute: AttributeAllowedCidrV4,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ipn,
	})
	t.Logf("CidrV4 value: %#v", *ipn)
	t.Logf("CidrV4 fact: %#v", f)
	t.Logf("CidrV4 packet: %v", p)

	f = mustDeserialize(t, p)

	assert.Equal(t, AttributeAllowedCidrV4, f.Attribute)

	require.IsType(t, &PeerSubject{}, f.Subject)
	assert.Equal(t, key, f.Subject.(*PeerSubject).Key)

	require.IsType(t, &IPNetValue{}, f.Value)
	assert.Equal(t, ipn.IP, f.Value.(*IPNetValue).IP)
	assert.Equal(t, ipn.Mask, f.Value.(*IPNetValue).Mask)
}

func TestParseCidrV6(t *testing.T) {
	ipn := &IPNetValue{
		IPNet: net.IPNet{
			IP:   mustRandBytes(t, make([]byte, net.IPv6len)),
			Mask: net.CIDRMask(rand.Intn(8*net.IPv6len), 8*net.IPv6len),
		},
	}
	key := mustKey(t)

	f, p := mustSerialize(t, &Fact{
		Attribute: AttributeAllowedCidrV6,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ipn,
	})
	t.Logf("CidrV6 packet: %v", p)

	f = mustDeserialize(t, p)

	assert.Equal(t, AttributeAllowedCidrV6, f.Attribute)

	require.IsType(t, &PeerSubject{}, f.Subject)
	assert.Equal(t, key, f.Subject.(*PeerSubject).Key)

	require.IsType(t, &IPNetValue{}, f.Value)
	assert.Equal(t, ipn.IP, f.Value.(*IPNetValue).IP)
	assert.Equal(t, ipn.Mask, f.Value.(*IPNetValue).Mask)
}
