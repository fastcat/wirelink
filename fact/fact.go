package fact

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/fastcat/wirelink/util"
)

// fact types, denoted as attributes of a subject
const (
	AttributeUnknown        Attribute = 0
	AttributeAlive          Attribute = '!'
	AttributeEndpointV4     Attribute = 'e'
	AttributeEndpointV6     Attribute = 'E'
	AttributeAllowedCidrV4  Attribute = 'a'
	AttributeAllowedCidrV6  Attribute = 'A'
	AttributeMember         Attribute = 'm'
	AttributeMemberMetadata Attribute = 'M'
	// A signed group is a bit different from other facts
	// in this case, the subject is actually the source,
	// and the value is a signed aggregate of other facts.
	AttributeSignedGroup Attribute = 'S'
)

// Fact represents a single piece of information about a subject, with an
// associated expiration time
type Fact struct {
	encoding.BinaryMarshaler
	util.Decodable

	Attribute Attribute
	Expires   time.Time
	Subject   Subject
	Value     Value
}

func (f *Fact) String() string {
	return f.FancyString(func(s Subject) string { return s.String() }, time.Now())
}

// FancyString formats the fact as a string using a custom helper to format
// the subject, most commonly to replace peer keys with names
func (f *Fact) FancyString(
	subjectFormatter func(s Subject) string,
	now time.Time,
) string {
	if f == nil {
		return fmt.Sprintf("%v", nil)
	}
	return fmt.Sprintf(
		"{a:%c s:%s v:%s ttl:%.3f}",
		f.Attribute,
		subjectFormatter(f.Subject),
		f.Value,
		f.Expires.Sub(now).Seconds(),
	)
}

// MarshalBinary serializes a Fact to its on-wire format
func (f *Fact) MarshalBinary() ([]byte, error) {
	return f.MarshalBinaryNow(time.Now())
}

// MarshalBinaryNow is like MarshalBinary, except it uses a provided value of
// `now` so that the output is deterministic
func (f *Fact) MarshalBinaryNow(now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	var tmp [binary.MaxVarintLen64]byte
	var tmpLen int

	buf.WriteByte(byte(f.Attribute))

	ttl := f.Expires.Sub(now) / time.Second
	// clamp ttl to uint16 range
	// TODO: warn if we somehow get outside this range
	if ttl < 0 {
		ttl = 0
	} else if ttl > math.MaxUint16 {
		ttl = math.MaxUint16
	}
	tmpLen = binary.PutUvarint(tmp[:], uint64(ttl))
	if n, err := buf.Write(tmp[0:tmpLen]); err != nil || n != tmpLen {
		return buf.Bytes(), util.WrapOrNewf(err, "failed to write ttl bytes, wrote %d of %d", n, tmpLen)
	}

	// these should never return errors, but ...

	subjectData, err := f.Subject.MarshalBinary()
	if err != nil {
		return buf.Bytes(), fmt.Errorf("failed to marshal Subject: %w", err)
	}
	if n, err := buf.Write(subjectData); err != nil || n != len(subjectData) {
		return buf.Bytes(), util.WrapOrNewf(err, "failed to write subject to buffer, wrote %d of %d", n, len(subjectData))
	}

	valueData, err := f.Value.MarshalBinary()
	if err != nil {
		return buf.Bytes(), fmt.Errorf("failed to marshal Value: %w", err)
	}
	if n, err := buf.Write(valueData); err != nil || n != len(valueData) {
		return buf.Bytes(), util.WrapOrNewf(err, "failed to write Value to buffer, wrote %d of %d", n, len(valueData))
	}

	return buf.Bytes(), nil
}
