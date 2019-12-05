package fact

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TTLClamping(t *testing.T) {
	// going to modify the fact before serializing it
	f, _ := mustMockAlivePacket(t, nil, nil)
	// needs to be +2 so that forwards movement of the clock combined with
	// rounding errors don't cause it to miss the clamping branch
	f.Expires = time.Now().Add(time.Second * (math.MaxUint16 + 2))
	_, p := mustSerialize(t, f)

	// TODO: find a cleaner way to verify serialization-time clamping
	ttl, n := binary.Uvarint(p[1:])
	assert.LessOrEqual(t, n, binary.MaxVarintLen16)
	assert.Equal(t, uint64(math.MaxUint16), ttl)

	// TODO: find a cleaner way to verify deserialization-time clamping
	n2 := binary.PutUvarint(p[1:], math.MaxUint16+1)
	// hack won't work if the length changes
	require.Equal(t, n, n2)

	f = &Fact{}
	err := f.DecodeFrom(len(p), bytes.NewBuffer(p))
	if assert.Error(t, err, "Decoding fact with out of range TTL should fail") {
		// FIXME: this is a terrible way to check the error
		assert.Contains(t, err.Error(), "range")
		assert.Contains(t, err.Error(), strconv.Itoa(math.MaxUint16+1))
	}
}

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

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, key, f.Subject.(*PeerSubject).Key)
	}

	if assert.IsType(t, &IPPortValue{}, f.Value) {
		assert.Equal(t, ep.IP, f.Value.(*IPPortValue).IP)
		assert.Equal(t, ep.Port, f.Value.(*IPPortValue).Port)
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

	assert.Equal(t, AttributeEndpointV6, f.Attribute)

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, key, f.Subject.(*PeerSubject).Key)
	}

	if assert.IsType(t, &IPPortValue{}, f.Value) {
		assert.Equal(t, ep.IP, f.Value.(*IPPortValue).IP)
		assert.Equal(t, ep.Port, f.Value.(*IPPortValue).Port)
	}
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

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, key, f.Subject.(*PeerSubject).Key)
	}

	if assert.IsType(t, &IPNetValue{}, f.Value) {
		assert.Equal(t, ipn.IP, f.Value.(*IPNetValue).IP)
		assert.Equal(t, ipn.Mask, f.Value.(*IPNetValue).Mask)
	}
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

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, key, f.Subject.(*PeerSubject).Key)
	}

	if assert.IsType(t, &IPNetValue{}, f.Value) {
		assert.Equal(t, ipn.IP, f.Value.(*IPNetValue).IP)
		assert.Equal(t, ipn.Mask, f.Value.(*IPNetValue).Mask)
	}
}
