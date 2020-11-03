package fact

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"

	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/util"
)

// MemberAttribute is a single byte identifying some attribute of a member.
type MemberAttribute byte

const (
	// MemberName is the friendly / display name to use for a peer
	MemberName MemberAttribute = 'n'
	// MemberIsBasic flags if the member is a "basic" member which only runs
	// wireguard and not wirelink
	MemberIsBasic MemberAttribute = 'b'
)

// MemberMetadata represents a set of attributes and their values for a single
// peer.
type MemberMetadata struct {
	attributes map[MemberAttribute]string
}

var _ Value = &MemberMetadata{}

type stringValidator func(string) error

// memberMetadataValidators provides a lookup table for validating the inner
// elements of a MemberMetadata value
var memberMetadataValidators map[MemberAttribute]stringValidator = map[MemberAttribute]stringValidator{
	MemberName: func(value string) error {
		if !utf8.ValidString(value) {
			return errors.Errorf("Invalid string for MemberName: %q", value)
		}
		return nil
	},
	MemberIsBasic: func(value string) error {
		if len(value) != 1 {
			return errors.Errorf("Invalid boolean for MemberIsBasic, len=%d", len(value))
		}
		if value[0] != 0 && value[0] != 1 {
			return errors.Errorf("Invalid boolean for MemberIsBasic, value=%d", int(value[0]))
		}
		return nil
	},
}

// MarshalBinary implements BinaryEncoder
func (mm *MemberMetadata) MarshalBinary() ([]byte, error) {
	// start the buffer out with enough room for the length bytes that will be
	// added at the end, plus a guess at the smallest possible size for the
	// attribute data
	buf := make([]byte, binary.MaxVarintLen16, binary.MaxVarintLen16+len(mm.attributes)*(1+binary.MaxVarintLen16))

	// temp buffer and size for doing uvarint encodings
	tmp := make([]byte, binary.MaxVarintLen64)
	var l int

	// important to sort the attributes for equality checks to work properly
	attrs := mm.sortedAttrs()
	for _, a := range attrs {
		v := mm.attributes[a]
		validator := memberMetadataValidators[a]
		if validator != nil {
			if err := validator(v); err != nil {
				return nil, errors.Wrap(err, "Invalid member attribute value")
			}
		} else {
			// this is at debug because we re-send stuff we got from elsewhere
			log.Debug("Encoding unrecognized member attribute %d", int(a))
		}
		buf = append(buf, byte(a))
		l = binary.PutUvarint(tmp, uint64(len(v)))
		buf = append(buf, tmp[:l]...)
		buf = append(buf, v...)
	}

	l = binary.PutUvarint(tmp, uint64(len(buf)-binary.MaxVarintLen16))
	if l > binary.MaxVarintLen16 {
		return nil, errors.Errorf("Member attributes length overflow: %d -> %d > 65535", len(mm.attributes), l)
	}

	// place the length bytes so that they abut the start of the data
	start := binary.MaxVarintLen16 - l
	copy(buf[start:], tmp[:l])

	return buf[start:], nil
}

func (mm *MemberMetadata) sortedAttrs() []MemberAttribute {
	attrs := make([]MemberAttribute, 0, len(mm.attributes))
	for a := range mm.attributes {
		attrs = append(attrs, a)
	}
	sort.Slice(attrs, func(i, j int) bool {
		// special case: always put the name attribute first, for cosmetic reasons
		if attrs[i] == MemberName {
			return true
		} else if attrs[j] == MemberName {
			return false
		} else {
			return attrs[i] < attrs[j]
		}
	})
	return attrs
}

// DecodeFrom implements Decodable
func (mm *MemberMetadata) DecodeFrom(lengthHint int, reader io.Reader) error {
	var br io.ByteReader
	var ok bool
	if br, ok = reader.(io.ByteReader); !ok {
		return errors.New("Cannot decode without a ByteReader")
	}
	payloadLen, err := binary.ReadUvarint(br)
	if err != nil {
		return errors.Wrap(err, "Unable to read metadata length")
	}
	// TODO: trace the calls to ReadByte from the above, so that we can validate
	// we don't exceed lengthHint. Not important as we expect lengthHint to be
	// zero always for this value type

	payload := make([]byte, payloadLen)
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return errors.Wrap(err, "Unable to read member attributes payload")
	}

	mm.attributes = make(map[MemberAttribute]string)
	for p := 0; p < len(payload); {
		a := MemberAttribute(payload[p])
		p++
		al, n := binary.Uvarint(payload[p:])
		if n <= 0 {
			return errors.Errorf("varint encoding error in attribute at payload offset %d", p-n)
		}
		p += n
		if p+int(al) > len(payload) {
			return errors.Errorf("attribute length error at payload offset %d: +%d>%d", p, al, len(payload))
		}
		v := string(payload[p : p+int(al)])
		p += int(al)

		validator := memberMetadataValidators[a]
		if validator != nil {
			if err := validator(v); err != nil {
				return errors.Wrap(err, "Invalid member attribute value")
			}
		} else {
			// not an error, we'll just ignore this value
			log.Info("Decoding unrecognized member attribute %d", int(a))
		}

		mm.attributes[a] = v
	}

	return nil
}

func (mm *MemberMetadata) String() string {
	// TODO: this could be better
	if len(mm.attributes) == 0 {
		return "(empty)"
	}

	ret := &strings.Builder{}
	numPrinted := 0
	attrs := mm.sortedAttrs()
	for _, a := range attrs {
		if numPrinted > 0 {
			ret.WriteRune(',')
		}
		// some attributes are binary, so they need to be quoted (%q)
		fmt.Fprintf(ret, "%c:%q", a, mm.attributes[a])
		numPrinted++
		if numPrinted > 2 || ret.Len() >= 32 {
			break
		}
	}
	if len(mm.attributes) > numPrinted {
		fmt.Fprintf(ret, ",+%d", len(mm.attributes)-numPrinted)
	}
	return ret.String()
}

/*

// Has returns whether the given MemberAttribute is present in the metadata
func (mm *MemberMetadata) Has(attr MemberAttribute) bool {
	_, ok := mm.attributes[attr]
	return ok
}

// Get returns the given MemberAttribute or the empty string if not present
func (mm *MemberMetadata) Get(attr MemberAttribute) string {
	return mm.attributes[attr]
}

// TryGet returns the given MemberAttribute or the empty string,
// and whether or not it was present.
func (mm *MemberMetadata) TryGet(attr MemberAttribute) (string, bool) {
	val, ok := mm.attributes[attr]
	return val, ok
}

*/

// ForEach calls visitor for each attribute in the metadata.
func (mm *MemberMetadata) ForEach(visitor func(MemberAttribute, string)) {
	for a, v := range mm.attributes {
		visitor(a, v)
	}
}

// With returns a copy of the member metadata with the given info updated: name
// will be assigned if non-empty, basic will be assigned if true, or if not
// present in the initial value.
func (mm *MemberMetadata) With(name string, basic bool) *MemberMetadata {
	ret := *mm
	if ret.attributes == nil {
		ret.attributes = make(map[MemberAttribute]string, 2)
	}
	if len(name) != 0 {
		ret.attributes[MemberName] = name
	}
	if _, ok := ret.attributes[MemberIsBasic]; basic || !ok {
		ret.attributes[MemberIsBasic] = util.Ternary(basic, string(byte(1)), string(byte(0))).(string)
	}
	return &ret
}
