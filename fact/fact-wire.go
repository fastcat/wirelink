package fact

import (
	"fmt"
	"unicode/utf8"
)

// OnWire is the intermediate representation of fact packet on the wire
type OnWire struct {
	attribute byte
	ttl       uint8
	subject   []byte
	value     []byte
}

// Serialize turns an on-the-wire fact into  a byte array that can be sent
func (f *OnWire) Serialize() ([]byte, error) {
	if len(f.subject) < 1 || len(f.subject) > 255 {
		return nil, fmt.Errorf("subject length %d is out of range", len(f.subject))
	}
	// value can be empty for "ping" packets
	// value of 255 is a special case that means there
	if len(f.value) > utf8.MaxRune {
		return nil, fmt.Errorf("value length %d is out of range (must be <= %d)", len(f.value), utf8.MaxRune)
	}
	// packet length is 1 byte for attribute, 1 byte for ttl, 1 byte for subject length,
	// 1-4 bytes for value length, N bytes for subject, and N bytes for value
	valueLenLen := utf8.RuneLen(rune(len(f.value)))
	ret := make([]byte, 0, 4+len(f.subject)+valueLenLen+len(f.value))
	ret = append(ret, f.attribute, f.ttl, byte(len(f.subject)))
	p := len(ret)
	ret = ret[0 : p+valueLenLen]
	utf8.EncodeRune(ret[p:p+valueLenLen], rune(len(f.value)))
	ret = append(ret, f.subject...)
	ret = append(ret, f.value...)
	return ret, nil
}

// Deserialize tries to turn a packet from the wire into the intermediate structure
func Deserialize(data []byte) (*OnWire, error) {
	ret, remainder, err := deserializeSlice(data)
	if err != nil {
		return nil, err
	}
	if len(remainder) != 0 {
		return nil, fmt.Errorf("Data is too long for header values")
	}
	return ret, nil
}

// deserializeSlice tries to read the first valid fact out of a buffer into the intermediate structure,
// returning that and the remainder of the buffer, and any error
func deserializeSlice(data []byte) (*OnWire, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("data is impossibly short")
	}

	attribute := data[0]
	ttl := data[1]
	subjectLen := int(data[2])
	if !utf8.FullRune(data[3:]) {
		return nil, nil, fmt.Errorf("value length encoding is invalid")
	}
	r, valueLenLen := utf8.DecodeRune(data[3:])
	valueLen := int(r)
	// skip data past the header
	data = data[3+valueLenLen:]

	if len(data) < subjectLen+valueLen {
		return nil, nil, fmt.Errorf("data is too short for header values: %d < %d+%d", len(data), subjectLen, valueLen)
	}

	subject := make([]byte, subjectLen)
	copy(subject, data[0:subjectLen])
	value := make([]byte, valueLen)
	copy(value, data[subjectLen:subjectLen+valueLen])

	return &OnWire{
		attribute: attribute,
		ttl:       ttl,
		subject:   subject,
		value:     value,
	}, data[subjectLen+valueLen:], nil
}
