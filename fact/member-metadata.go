package fact

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/pkg/errors"
)

type MemberAttribute byte

const (
	MemberName MemberAttribute = 'n'
)

type MemberMetadata struct {
	attributes map[MemberAttribute]string
}

var _ Value = &MemberMetadata{}

// MarshalBinary implements BinaryEncoder
func (mm *MemberMetadata) MarshalBinary() ([]byte, error) {
	// start the buffer out with enough room for the length bytes that will be
	// added at the end, plus a guess at the smallest possible size for the
	// attribute data
	buf := make([]byte, binary.MaxVarintLen16, binary.MaxVarintLen16+len(mm.attributes)*(1+binary.MaxVarintLen16))

	// temp buffer and size for doing uvarint encodings
	tmp := make([]byte, binary.MaxVarintLen64)
	var l int

	for a, v := range mm.attributes {
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
	l, err := reader.Read(payload)
	if err != nil || uint64(l) != payloadLen {
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
			return errors.Errorf("attribute length error at payload offset %d", p)
		}
		mm.attributes[a] = string(payload[p : p+int(al)])
	}

	return nil
}

func (mm *MemberMetadata) String() string {
	// TODO: this could be better
	if len(mm.attributes) == 0 {
		return "(empty)"
	}

	ret := &strings.Builder{}
	for a, v := range mm.attributes {
		fmt.Fprintf(ret, "%c:%s", a, v)
		break
	}
	if len(mm.attributes) > 1 {
		fmt.Fprintf(ret, ",%d more", len(mm.attributes)-1)
	}
	return ret.String()
}
