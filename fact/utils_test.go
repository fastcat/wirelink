package fact

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stretchr/testify/require"

	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustMockAlivePacket(t *testing.T, subject *wgtypes.Key, id *uuid.UUID) (*Fact, []byte) {
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

func mustSerialize(t *testing.T, f *Fact) (*Fact, []byte) {
	p, err := f.MarshalBinary()
	require.Nil(t, err)
	return f, p
}

func mustDeserialize(t *testing.T, p []byte) (f *Fact) {
	f = &Fact{}
	err := f.DecodeFrom(len(p), bytes.NewBuffer(p))
	require.Nil(t, err)
	// to help verify data races, randomize the input buffer after its consumed,
	// so that any code that hangs onto it will show clear test failures
	testutils.MustRandBytes(t, p)
	return
}
