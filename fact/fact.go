package fact

import (
	"fmt"
	"time"
)

// fact types, denoted as attributes of a subject
const (
	AttributeUnknown       Attribute = 0
	AttributeEndpointV4    Attribute = 'e'
	AttributeEndpointV6    Attribute = 'E'
	AttributeAllowedCidrV4 Attribute = 'a'
	AttributeAllowedCidrV6 Attribute = 'A'
	// A signed group is a bit different from other facts
	// in this case, the subject is actually the source,
	// and the value
	AttributeSignedGroup Attribute = 'S'
)

// Fact represents a single piece of information about a subject, with an
// associated expiration time
type Fact struct {
	Attribute Attribute
	Expires   time.Time
	Subject   Subject
	Value     Value
}

func (f *Fact) String() string {
	if f == nil {
		return fmt.Sprintf("%v", nil)
	}
	return fmt.Sprintf(
		"{a:%c s:%s v:%s ttl:%.3f}",
		f.Attribute,
		f.Subject,
		f.Value,
		f.Expires.Sub(time.Now()).Seconds(),
	)
}

// ToWire turns a structured fact into its intermediate wire format
func (f *Fact) ToWire() (p *OnWire, err error) {
	ttl := f.Expires.Sub(time.Now()) / time.Second
	if ttl < 0 {
		ttl = 0
	} else if ttl > 255 {
		ttl = 255
	}
	return &OnWire{
		attribute: byte(f.Attribute),
		ttl:       uint8(ttl),
		subject:   f.Subject.Bytes(),
		value:     f.Value.Bytes(),
	}, nil
}
