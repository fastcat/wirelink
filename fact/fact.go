package fact

import (
	"fmt"
	"time"

	"github.com/fastcat/wirelink/fact/types"
)

// fact types, denoted as attributes of a subject
const (
	AttributeUnknown       types.Attribute = 0
	AttributeEndpointV4    types.Attribute = 'e'
	AttributeEndpointV6    types.Attribute = 'E'
	AttributeAllowedCidrV4 types.Attribute = 'a'
	AttributeAllowedCidrV6 types.Attribute = 'A'
)

// Fact represents a single piece of information about a subject, with an
// associated expiration time
type Fact struct {
	Attribute types.Attribute
	Expires   time.Time
	Subject   types.Subject
	Value     types.Value
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
	if f == nil {
		return nil, fmt.Errorf("fact is nil")
	}

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
