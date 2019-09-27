package fact

import "fmt"

// representation of fact on the wire
type FactOnWire struct {
	attribute byte
	ttl       uint8
	subject   []byte
	value     []byte
}

func (f *FactOnWire) Serialize() ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("Fact is nil")
	}
	if f.subject == nil || f.value == nil {
		return nil, fmt.Errorf("subject or value is nil")
	}
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
