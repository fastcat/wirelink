package testutils

import (
	"math/rand"

	"testing"

	"github.com/stretchr/testify/require"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MustKeyPair generates a real pair of private and public keys,
// panicing (via require) if this fails
func MustKeyPair(t *testing.T) (privateKey, publicKey wgtypes.Key) {
	priv, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	pub := priv.PublicKey()
	return priv, pub
}

// MustKey uses MustRandBytes to generate a random (not crypto-valid) key
func MustKey(t *testing.T) (key wgtypes.Key) {
	MustRandBytes(t, key[:])
	return
}

// MustRandBytes fills the given slice with random bytes using rand.Read
func MustRandBytes(t *testing.T, data []byte) []byte {
	n, err := rand.Read(data)
	require.Nil(t, err)
	require.Equal(t, len(data), n)
	return data
}
