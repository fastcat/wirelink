package fact

import (
	"encoding"
	"fmt"

	"github.com/fastcat/wirelink/util"
)

// Subject is the subject of a Fact
type Subject interface {
	fmt.Stringer
	encoding.BinaryMarshaler
	util.Decodable
}

// Value represents the value of a Fact
type Value interface {
	fmt.Stringer
	encoding.BinaryMarshaler
	util.Decodable
}

// Attribute is a byte identifying what aspect of a Subject a Fact describes
type Attribute byte
