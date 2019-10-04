package fact

import "fmt"

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
	if len(f.value) < 1 || len(f.value) > 255 {
		return nil, fmt.Errorf("value length %d is out of range", len(f.value))
	}
	ret := make([]byte, 0, 4+len(f.subject)+len(f.value))
	ret = append(ret, f.attribute, f.ttl, byte(len(f.subject)), byte(len(f.value)))
	ret = append(ret, f.subject...)
	ret = append(ret, f.value...)
	return ret, nil
}

// Deserialize tries to turn a packet from the wire into the intermediate structure
func Deserialize(data []byte) (*OnWire, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data is impossibly short")
	}

	attribute := data[0]
	ttl := data[1]
	subjectLen := data[2]
	valueLen := data[3]

	if len(data) != 4+int(subjectLen)+int(valueLen) {
		return nil, fmt.Errorf("data is too short for header values")
	}

	subject := make([]byte, subjectLen)
	copy(subject, data[4:4+subjectLen])
	value := make([]byte, valueLen)
	copy(value, data[4+subjectLen:])

	return &OnWire{
		attribute: attribute,
		ttl:       ttl,
		subject:   subject,
		value:     value,
	}, nil
}
