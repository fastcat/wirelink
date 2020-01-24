package signing

import (
	"crypto/rand"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SignFor makes a signature to send data to a given peer
func (s *Signer) SignFor(
	data []byte,
	peer *wgtypes.Key,
) (
	nonce [chacha20poly1305.NonceSizeX]byte,
	tag [poly1305.TagSize]byte,
	err error,
) {
	sk := s.sharedKey(peer)
	if _, err = rand.Read(nonce[:]); err != nil {
		return
	}
	cipher, err := chacha20poly1305.NewX(sk[:])
	if err != nil {
		return
	}
	out := cipher.Seal(nil, nonce[:], nil, data)
	if len(out) != len(tag) {
		err = errors.Errorf("Unexpected output length %d from AEAD, expected %d", len(out), len(tag))
		return
	}
	copy(tag[:], out[:])
	return
}
