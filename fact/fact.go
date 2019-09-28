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
)

// Attribute is a byte identifying what aspect of a Subject a Fact describes
type Attribute byte

// Fact represents a single piece of information about a subject, with an
// associated expiration time
type Fact struct {
	Attribute Attribute
	Expires   time.Time
	Subject   Subject
	Value     Value
}

// Subject is the subject of a Fact
type Subject interface {
	fmt.Stringer
	Bytes() []byte
}

// Value represents the value of a Fact
type Value interface {
	fmt.Stringer
	Bytes() []byte
}

func (f Fact) String() string {
	return fmt.Sprintf(
		"{a:%c s:%s v:%s ttl:%.3f}",
		f.Attribute,
		f.Subject,
		f.Value,
		f.Expires.Sub(time.Now()).Seconds(),
	)
}
