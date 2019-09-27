package fact

import "time"

// fact types, denoted as attributes of a subject
const (
	AttributeUnknown       = 0
	AttributeEndpointV4    = 'e'
	AttributeEndpointV6    = 'E'
	AttributeAllowedCidrV4 = 'a'
	AttributeAllowedCidrv6 = 'A'
)

type Fact struct {
	Attribute byte
	Expires   time.Time
	Subject   []byte
	Value     []byte
}
