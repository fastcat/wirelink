package trust

import (
	"net"

	"github.com/fastcat/wirelink/fact"
)

// Evaluator is an interface for implementations that can answer whether
// a fact received from a remote source should be trusted and accepted into
// the set of locally known facts
type Evaluator interface {
	IsTrusted(fact *fact.Fact, source net.IP) bool
}
