package signing

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SignFor makes a signature to send data to a given peer
func (s *Signer) SignFor(
	data []byte,
	peer *wgtypes.Key,
) (
	nonce [chacha20poly1305.NonceSizeX]byte,
	tag [chacha20poly1305.Overhead]byte,
	err error,
) {
	sk, err := s.sharedKey(peer)
	if err != nil {
		return nonce, tag, err
	}
	if _, err = rand.Read(nonce[:]); err != nil {
		return nonce, tag, err
	}
	cipher, err := chacha20poly1305.NewX(sk[:])
	if err != nil {
		return nonce, tag, err
	}
	out := cipher.Seal(nil, nonce[:], nil, data)
	if len(out) != len(tag) {
		err = fmt.Errorf("unexpected output length %d from AEAD, expected %d", len(out), len(tag))
		return nonce, tag, err
	}
	copy(tag[:], out[:])
	return nonce, tag, err
}
