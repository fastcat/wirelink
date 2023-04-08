package fact

import (
	"fmt"
	"io"

	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerSubject is a subject that is a peer identified via its public key
type PeerSubject struct {
	wgtypes.Key
}

// MarshalBinary implements encoding.BinaryMarshaler
func (s *PeerSubject) MarshalBinary() ([]byte, error) {
	return s.Key[:], nil
}

// UnmarshalBinary implements BinaryUnmarshaler
func (s *PeerSubject) UnmarshalBinary(data []byte) error {
	if len(data) != wgtypes.KeyLen {
		return fmt.Errorf("data len wrong for peer subject")
	}
	copy(s.Key[:], data)
	return nil
}

// DecodeFrom implements Decodable
func (s *PeerSubject) DecodeFrom(_ int, reader io.Reader) error {
	return util.DecodeFrom(s, wgtypes.KeyLen, reader)
}

// IsSubject implements Subject
func (s *PeerSubject) IsSubject() {}

// *PeerSubject must implement Subject
// we do this with the pointer because if we do it with the struct, the pointer
// matches too, and that confuses things, and critically because unmarshalling
// and decoding require mutation of the value
var _ Subject = &PeerSubject{}
