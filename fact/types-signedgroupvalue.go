package fact

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/fastcat/wirelink/util"
	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SignedGroupValue represents a signed chunk of other fact data.
// Note that this structure does _not_ include parsing those inner bytes!
type SignedGroupValue struct {
	Nonce      [chacha20poly1305.NonceSizeX]byte
	Tag        [poly1305.TagSize]byte
	InnerBytes []byte
}

var _ Value = &SignedGroupValue{}

const sgvOverhead = chacha20poly1305.NonceSizeX + poly1305.TagSize

// UDPMaxSafePayload is the maximum payload size of a UDP packet we can safely send.
// we only need to worry about IPv6 for this
const UDPMaxSafePayload = 1212

// attribute + ttl varint worst case + subject (key) length
const sgvFactOverhead = 1 + binary.MaxVarintLen16 + wgtypes.KeyLen

// SignedGroupMaxSafeInnerLength is the maximum safe length for `InnerBytes`
// above which fragmentation or packet drops may happen. This is computed based
// on the max safe UDP payload for IPv6, minus the fact & crypto overheads.
const SignedGroupMaxSafeInnerLength = UDPMaxSafePayload - sgvFactOverhead - sgvOverhead

// MarshalBinary gives the on-wire form of the value
func (sgv *SignedGroupValue) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 0, len(sgv.Nonce)+len(sgv.Tag)+len(sgv.InnerBytes))
	ret = append(ret, sgv.Nonce[:]...)
	ret = append(ret, sgv.Tag[:]...)
	ret = append(ret, sgv.InnerBytes...)
	return ret, nil
}

// DecodeFrom implements Decodable
func (sgv *SignedGroupValue) DecodeFrom(lengthHint int, reader io.Reader) error {
	// TODO: generic reader support
	var buf *bytes.Buffer
	var ok bool
	if buf, ok = reader.(*bytes.Buffer); !ok {
		return fmt.Errorf("Reading SignedGroupValue is only supported from a Buffer, not a %T", reader)
	}

	var n int
	var err error

	if n, err = reader.Read(sgv.Nonce[:]); err != nil || n != len(sgv.Nonce) {
		return util.WrapOrNewf(err, "Failed to read Nonce for SignedGroupValue, got %d of %d bytes", n, len(sgv.Nonce))
	}
	if n, err = reader.Read(sgv.Tag[:]); err != nil || n != len(sgv.Tag) {
		return util.WrapOrNewf(err, "Failed to read Tag for SignedGroupValue, got %d of %d bytes", n, len(sgv.Tag))
	}
	// IMPORTANT: because we may be parsing from a packet buffer, we MUST NOT
	// keep a reference to the data buffer after we return
	sgv.InnerBytes = util.CloneBytes(buf.Bytes())

	return nil
}

// ParseInner parses the inner bytes of a SignedGroupValue into facts.
// Validating the signature must be done separately, and should be done before
// calling this method.
func (sgv *SignedGroupValue) ParseInner() (ret []*Fact, err error) {
	buf := bytes.NewBuffer(sgv.InnerBytes)
	for buf.Len() != 0 {
		// TODO: bytes[0] or readbyte/unreadbyte?
		if buf.Bytes()[0] == byte(AttributeSignedGroup) {
			err = errors.Errorf("SignedGroups must not be nested at #%d @%d", len(ret), buf.Len()-len(sgv.InnerBytes))
			return
		}
		next := &Fact{}
		if err = next.DecodeFrom(0, buf); err != nil {
			err = errors.Wrapf(err, "Unable to decode SignedGroupValue inner #%d @%d", len(ret), buf.Len()-len(sgv.InnerBytes))
			return
		}
		ret = append(ret, next)
	}
	return
}

func (sgv *SignedGroupValue) String() string {
	// could parse the inner bytes for this, but probably not worth it
	return fmt.Sprintf("{SGV: %d bytes}", len(sgv.InnerBytes))
}
