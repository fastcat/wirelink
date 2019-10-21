package trust

import (
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

func (c *composite) TrustLevel(fact *fact.Fact, source net.IP) (ret Level) {
	first := false
	for _, e := range c.inner {
		if !e.IsKnown(fact.Subject) {
			continue
		}
		l := e.TrustLevel(fact, source)
		if c.mode == FirstOnly {
			return l
		} else if c.mode == LeastPermission && (first || l < ret) {
			ret = l
		} else if c.mode == MostPermission && (first || l > ret) {
			ret = l
		}
		first = false
	}
	return
}
