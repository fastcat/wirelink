package trust

import (
	"fmt"
	"net"

	"github.com/fastcat/wirelink/fact"
)

// CompositeMode is an enum for how a composite evaluator combines the results
// of its member evaluators
type CompositeMode int

const (
	// FirstOnly composites return the trust level from the first evaluator that
	// knows the subject
	FirstOnly CompositeMode = iota
	// LeastPermission composites return the lowest trust level from the evaluators
	// that know the subject
	LeastPermission
	// MostPermission composites return the highest trust level from the evaluators
	// that known the subject
	MostPermission
)

func (cm CompositeMode) String() string {
	switch cm {
	case FirstOnly:
		return "FirstOnly"
	case LeastPermission:
		return "LeastPermission"
	case MostPermission:
		return "MostPermission"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", cm)
	}
}

// CreateComposite generates an evaluator which combines the results of others
// using the specified mode
func CreateComposite(mode CompositeMode, evaluators ...Evaluator) Evaluator {
	return &composite{
		mode:  mode,
		inner: evaluators,
	}
}

type composite struct {
	mode  CompositeMode
	inner []Evaluator
}

// *composite should implement Evaluator
var _ Evaluator = &composite{}

func (c *composite) IsKnown(subject fact.Subject) bool {
	for _, e := range c.inner {
		if e.IsKnown(subject) {
			return true
		}
	}
	return false
}

func (c *composite) TrustLevel(fact *fact.Fact, source net.UDPAddr) (ret *Level) {
	for _, e := range c.inner {
		// IsKnown is orthogonal to TrustLevel, don't check it here
		l := e.TrustLevel(fact, source)
		if l == nil {
			continue
		} else if c.mode == FirstOnly {
			return l
		} else if c.mode == LeastPermission && (ret == nil || *l < *ret) {
			ret = l
		} else if c.mode == MostPermission && (ret == nil || *l > *ret) {
			ret = l
		}
	}
	return ret
}
