package signing

import (
	"crypto/rand"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/stretchr/testify/assert"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/require"
)

func TestSignAndVerify(t *testing.T) {
	key1, pubkey1 := testutils.MustKeyPair(t)
	key2, pubkey2 := testutils.MustKeyPair(t)

	signer1 := New(key1)
	signer2 := New(key2)

	sk1, err := signer1.sharedKey(&pubkey2)
	require.NoError(t, err)
	sk2, err := signer2.sharedKey(&pubkey1)
	require.NoError(t, err)
	assert.Equal(t, sk1, sk2, "Shared keys should compute equal")

	// this is a "random" value
	const dataLen = 87
	data := make([]byte, dataLen)
	_, err = rand.Read(data)
	if err != nil {
		t.Fatal("Unable to generate random data")
	}

	nonce, tag, err := signer1.SignFor(data, &pubkey2)
	if err != nil {
		t.Errorf("Failed to sign: %v", err)
	}

	valid, err := signer2.VerifyFrom(nonce, tag, data, &pubkey1)
	if err != nil {
		t.Errorf("Failed to verify: %v", err)
	}
	if !valid {
		t.Error("Signed data didn't validate")
	}

	// verify it fails if we muck with a byte
	tag[12]++

	valid, err = signer2.VerifyFrom(nonce, tag, data, &pubkey1)
	if valid || err == nil {
		t.Errorf("Incorrectly validated corrupted data")
	}
}

func TestSignErrors(t *testing.T) {
	var badKey wgtypes.Key
	var badPub wgtypes.Key
	goodKey, _ := testutils.MustKeyPair(t)
	signer := New(badKey)
	_, err := signer.sharedKey(&badPub)
	assert.Error(t, err)
	signer = New(goodKey)
	_, err = signer.sharedKey(&badPub)
	assert.Error(t, err)
}
