package signing

import (
	"crypto/rand"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSignAndVerify(t *testing.T) {
	key1, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal("Unable to generate a private key")
	}
	key2, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal("Unable to generate a private key")
	}
	pubkey1 := key1.PublicKey()
	pubkey2 := key2.PublicKey()

	signer1 := New(&key1)
	signer2 := New(&key2)

	sk1 := signer1.sharedKey(&pubkey2)
	sk2 := signer2.sharedKey(&pubkey1)
	if sk1 != sk2 {
		t.Errorf("Shared keys are unequal: %v / %v", sk1, sk2)
	}

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
