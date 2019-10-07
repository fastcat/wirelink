package trust

import (
	"net"

	"github.com/fastcat/wirelink/fact"
)

// Level is how much we should trust a fact received from a remote source
type Level int

// Returning Endpoint vs AllowedIPs is a bit redundant since the fact is one of
// those, but it makes the model clearer

const (
	// Untrusted means we should ignore the fact, as if we never received it
	Untrusted = iota
	// Endpoint means we should trust it enough to try endpoints we may have received
	Endpoint
	// AllowedIPs means we should trust it enough to add AllowedIPs to our local
	// configuration for the peer, if we can make a direct connection to it
	AllowedIPs
	// AddPeer means we should trust it enough to add it as a new peer in the
	// local configuration if we don't have it
	AddPeer
)

// Evaluator is an interface for implementations that can answer whether
// a fact received from a remote source should be trusted and accepted into
// the set of locally known facts
type Evaluator interface {
	// TrustLevel evaluates the trust level that should be applied to a fact given its source
	TrustLevel(fact *fact.Fact, source net.IP) Level
	// IsKnown checks whether the subject of a fact is already known to us
	IsKnown(subject fact.Subject) bool
}

// ShouldAccept checks whether a fact Atribute should be accepted at a given trust level
func ShouldAccept(attr fact.Attribute, known bool, level Level) bool {
	if !known {
		return level >= AddPeer
	}
	switch attr {
	case fact.AttributeEndpointV4:
		fallthrough
	case fact.AttributeEndpointV6:
		return level >= Endpoint

	case fact.AttributeAllowedCidrV4:
		fallthrough
	case fact.AttributeAllowedCidrV6:
		return level >= AllowedIPs
	}
	return false
}
