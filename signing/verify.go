package signing

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// VerifyFrom checks the signature on received data from a given peer
func (s *Signer) VerifyFrom(
	nonce [chacha20poly1305.NonceSizeX]byte,
	tag [poly1305.TagSize]byte,
	data []byte,
	peer *wgtypes.Key,
) (
	valid bool,
	err error,
) {
	sk := s.sharedKey(peer)
	var cipher cipher.AEAD
	cipher, err = chacha20poly1305.NewX(sk[:])
	if err != nil {
		return
	}
	_, err = cipher.Open(nil, nonce[:], tag[:], data)
	if err != nil {
		return false, err
	}
	valid = true
	return
}
