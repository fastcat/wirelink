package fact

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustMockAlivePacket(t *testing.T, subject *wgtypes.Key, id *uuid.UUID) (*Fact, *OnWire, []byte) {
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

func mustSerialize(t *testing.T, f *Fact) (*Fact, *OnWire, []byte) {
	w, err := f.ToWire()
	require.Nil(t, err)
	p, err := w.Serialize()
	require.Nil(t, err)
	return f, w, p
}

func mustDeserialize(t *testing.T, p []byte) (f *Fact, w *OnWire) {
	w, err := Deserialize(p)
	require.Nil(t, err)
	f, err = Parse(w)
	require.Nil(t, err)
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
