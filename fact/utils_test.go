package fact

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustEmptyPacket(t *testing.T) (*Fact, *OnWire, []byte) {
	return mustSerialize(t, &Fact{
		Attribute: AttributeUnknown,
		Subject:   &PeerSubject{},
		Expires:   time.Time{},
		Value:     EmptyValue{},
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

func mustKeyPair(t *testing.T) (privateKey, publicKey *wgtypes.Key) {
	priv, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	pub := priv.PublicKey()
	return &priv, &pub
}
