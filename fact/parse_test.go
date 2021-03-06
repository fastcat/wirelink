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

	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TTLClamping(t *testing.T) {
	now := time.Now()

	// going to modify the fact before serializing it
	f, _ := mustMockAlivePacket(t, nil, nil)
	// needs to be +2 so that forwards movement of the clock combined with
	// rounding errors don't cause it to miss the clamping branch
	f.Expires = now.Add(timeScale * (math.MaxUint16 + 2))
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
	err := f.DecodeFrom(len(p), now, bytes.NewBuffer(p))
	if assert.Error(t, err, "Decoding fact with out of range TTL should fail") {
		assert.Contains(t, err.Error(), "range")
		assert.Contains(t, err.Error(), strconv.Itoa(math.MaxUint16+1))
	}
}

func TestAccelerateTimeForTests(t *testing.T) {
	now := time.Now()
	ScaleExpirationQuantumForTests(10)
	defer ScaleExpirationQuantumForTests(1)

	f, _ := mustMockAlivePacket(t, nil, nil)
	f.Expires = now.Add(time.Second)
	p, err := f.MarshalBinaryNow(now)
	require.NoError(t, err)

	f = &Fact{}
	require.NoError(t, f.DecodeFrom(len(p), now, bytes.NewBuffer(p)))
	assert.Equal(t, now.Add(time.Second), f.Expires)

	ScaleExpirationQuantumForTests(1)
	f = &Fact{}
	require.NoError(t, f.DecodeFrom(len(p), now, bytes.NewBuffer(p)))
	assert.Equal(t, now.Add(10*time.Second), f.Expires)
}

func TestParseEndpointV4(t *testing.T) {
	now := time.Now()

	ep := &IPPortValue{
		IP:   testutils.MustRandBytes(t, make([]byte, net.IPv4len)),
		Port: 1,
	}
	key := testutils.MustKey(t)

	_, p := mustSerialize(t, &Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ep,
	})

	f := mustDeserialize(t, p, now)

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
	now := time.Now()

	ep := &IPPortValue{
		IP:   testutils.MustRandBytes(t, make([]byte, net.IPv6len)),
		Port: 1,
	}
	key := testutils.MustKey(t)

	_, p := mustSerialize(t, &Fact{
		Attribute: AttributeEndpointV6,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ep,
	})

	f := mustDeserialize(t, p, now)

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
	now := time.Now()

	ipn := &IPNetValue{
		IPNet: net.IPNet{
			IP:   testutils.MustRandBytes(t, make([]byte, net.IPv4len)),
			Mask: net.CIDRMask(rand.Intn(8*net.IPv4len), 8*net.IPv4len),
		},
	}
	key := testutils.MustKey(t)

	f, p := mustSerialize(t, &Fact{
		Attribute: AttributeAllowedCidrV4,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ipn,
	})
	t.Logf("CidrV4 value: %#v", *ipn)
	t.Logf("CidrV4 fact: %#v", f)
	t.Logf("CidrV4 packet: %v", p)

	f = mustDeserialize(t, p, now)

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
	now := time.Now()

	ipn := &IPNetValue{
		IPNet: net.IPNet{
			IP:   testutils.MustRandBytes(t, make([]byte, net.IPv6len)),
			Mask: net.CIDRMask(rand.Intn(8*net.IPv6len), 8*net.IPv6len),
		},
	}
	key := testutils.MustKey(t)

	_, p := mustSerialize(t, &Fact{
		Attribute: AttributeAllowedCidrV6,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     ipn,
	})
	t.Logf("CidrV6 packet: %v", p)

	f := mustDeserialize(t, p, now)

	assert.Equal(t, AttributeAllowedCidrV6, f.Attribute)

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, key, f.Subject.(*PeerSubject).Key)
	}

	if assert.IsType(t, &IPNetValue{}, f.Value) {
		assert.Equal(t, ipn.IP, f.Value.(*IPNetValue).IP)
		assert.Equal(t, ipn.Mask, f.Value.(*IPNetValue).Mask)
	}
}

func TestParseMember(t *testing.T) {
	now := time.Now()

	key := testutils.MustKey(t)

	_, p := mustSerialize(t, &Fact{
		Attribute: AttributeMember,
		Expires:   time.Time{},
		Subject:   &PeerSubject{Key: key},
		Value:     &EmptyValue{},
	})
	t.Logf("Member packet: %v", p)

	f := mustDeserialize(t, p, now)

	assert.Equal(t, AttributeMember, f.Attribute)

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, key, f.Subject.(*PeerSubject).Key)
	}

	assert.IsType(t, &EmptyValue{}, f.Value)
}

func TestFact_DecodeFrom(t *testing.T) {
	now := time.Now()

	type fields struct {
		Attribute Attribute
		Expires   time.Time
		Subject   Subject
		Value     Value
	}
	type args struct {
		lengthHint int
		data       []byte
	}
	tests := []struct {
		name       string
		args       args
		assertion  assert.ErrorAssertionFunc
		wantFields *fields
	}{
		{
			"AttributeUnknown error",
			args{0, []byte{byte(AttributeUnknown)}},
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.Contains(t, err.Error(), "AttributeUnknown") &&
					assert.Contains(t, err.Error(), "Legacy")
			},
			nil,
		},
		{
			"invalid attribute error",
			args{0, []byte{0xff}},
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.Contains(t, err.Error(), "Unrecognized attribute") &&
					assert.Contains(t, err.Error(), "0xff")
			},
			nil,
		},
		{
			"TTL read error",
			args{0, []byte{byte(AttributeAlive)}},
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.Contains(t, err.Error(), "ttl")
			},
			nil,
		},
		{
			"subject decode error",
			args{0, func() []byte {
				_, b := mustMockAlivePacket(t, nil, nil)
				return b[:len(b)-uuidLen-1]
			}()},
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.Contains(t, err.Error(), "subject")
			},
			nil,
		},
		{
			"value decode error",
			args{0, func() []byte {
				_, b := mustMockAlivePacket(t, nil, nil)
				return b[:len(b)-1]
			}()},
			func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.Error(t, err, msgAndArgs...) &&
					assert.Contains(t, err.Error(), "value")
			},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Fact{}
			tt.assertion(t, f.DecodeFrom(tt.args.lengthHint, now, bytes.NewBuffer(tt.args.data)))
			if tt.wantFields != nil {
				wantFact := &Fact{
					Attribute: tt.wantFields.Attribute,
					Expires:   tt.wantFields.Expires,
					Subject:   tt.wantFields.Subject,
					Value:     tt.wantFields.Value,
				}
				assert.Equal(t, wantFact, f)
			}
		})
	}
}
