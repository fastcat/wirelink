package signing

import (
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Signer represents a helper that does signing and verification
type Signer struct {
	privateKey wgtypes.Key
	PublicKey  wgtypes.Key
}

// New creates a new Signer using the given private key
func New(privateKey *wgtypes.Key) *Signer {
	return &Signer{
		privateKey: *privateKey,
		PublicKey:  privateKey.PublicKey(),
	}
}

func (s *Signer) sharedKey(peer *wgtypes.Key) [chacha20poly1305.KeySize]byte {
	var ret [chacha20poly1305.KeySize]byte
	curve25519.ScalarMult(&ret, (*[chacha20poly1305.KeySize]byte)(&s.privateKey), (*[chacha20poly1305.KeySize]byte)(peer))
	return ret
}
