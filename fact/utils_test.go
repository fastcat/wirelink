package fact

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustMockAlivePacket(t *testing.T, subject *wgtypes.Key, id *uuid.UUID) (*Fact, []byte) {
	if subject == nil {
		sk := mustKey(t)
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
	mustRandBytes(t, p)
	return
}

func mustKeyPair(t *testing.T) (privateKey, publicKey wgtypes.Key) {
	priv, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	pub := priv.PublicKey()
	return priv, pub
}

func mustKey(t *testing.T) (key wgtypes.Key) {
	mustRandBytes(t, key[:])
	return
}

func mustRandBytes(t *testing.T, data []byte) []byte {
	n, err := rand.Read(data)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	return data
}
