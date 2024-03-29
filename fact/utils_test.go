package fact

import (
	"bytes"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stretchr/testify/require"

	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustMockAlivePacket(t require.TestingT, subject *wgtypes.Key, id *uuid.UUID) (*Fact, []byte) {
	if subject == nil {
		sk := testutils.MustKey(t)
		subject = &sk
	}
	if id == nil {
		u := uuid.Must(uuid.NewRandom())
		id = &u
	}
	return mustSerialize(t, &Fact{
		Attribute: AttributeAlive,
		Subject:   &PeerSubject{Key: *subject},
		Expires:   time.Time{},
		Value:     &UUIDValue{UUID: *id},
	})
}

func mustMockAllowedV4Packet(t require.TestingT, subject *wgtypes.Key) (*Fact, []byte) {
	if subject == nil {
		sk := testutils.MustKey(t)
		subject = &sk
	}
	return mustSerialize(t, &Fact{
		Attribute: AttributeAllowedCidrV4,
		Subject:   &PeerSubject{Key: *subject},
		Expires:   time.Time{},
		Value:     &IPNetValue{makeIPNet(t)},
	})
}

// TODO: share with package apply
func makeIPNet(t require.TestingT) net.IPNet {
	return net.IPNet{
		IP:   testutils.MustRandBytes(t, make([]byte, net.IPv4len)),
		Mask: net.CIDRMask(1+rand.Intn(8*net.IPv4len), 8*net.IPv4len),
	}
}

func mustSerialize(t require.TestingT, f *Fact) (*Fact, []byte) {
	p, err := f.MarshalBinary()
	require.Nil(t, err)
	return f, p
}

func mustDeserialize(t *testing.T, p []byte, now time.Time) (f *Fact) {
	f = &Fact{}
	err := f.DecodeFrom(len(p), now, bytes.NewReader(p))
	require.Nil(t, err)
	// to help verify data races, randomize the input buffer after its consumed,
	// so that any code that hangs onto it will show clear test failures
	testutils.MustRandBytes(t, p)
	return
}
