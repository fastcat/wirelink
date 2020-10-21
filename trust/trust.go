// Package trust provides types and code for representing and evaluating trust
// levels of facts.
package trust

import (
	"net"
	"strconv"

	"github.com/fastcat/wirelink/fact"
)

// Level is how much we should trust a fact received from a remote source
type Level int

// Returning Endpoint vs AllowedIPs is a bit redundant since the fact is one of
// those, but it makes the model clearer

const (
	// Untrusted means we should ignore the fact, as if we never received it
	Untrusted Level = iota
	// Endpoint means we should trust it enough to try endpoints we may have received
	Endpoint
	// AllowedIPs means we should trust it enough to add AllowedIPs to our local
	// configuration for the peer, if we can make a direct connection to it
	AllowedIPs
	// Membership means that we trust it enough to determine which peers are part
	// of the network, adding peers it tells us should be members, and removing
	// those that no such trusted peer recognizes
	Membership
	// DelegateTrust means a peer is trusted to tell us the trust level of others
	DelegateTrust
)

// Values is a handy map to ease parsing strings to trust levels.
// NOTE: this is mutable, golang doesn't allow const/immutable maps
var Values map[string]Level = map[string]Level{
	"Untrusted":     Untrusted,
	"Endpoint":      Endpoint,
	"AllowedIPs":    AllowedIPs,
	"Membership":    Membership,
	"DelegateTrust": DelegateTrust,
}

// Names is a handy map to ease stringifying trust levels.
// NOTE: this is mutable, golang doesn't allow const/immutable maps
var Names map[Level]string = map[Level]string{
	Untrusted:     "Untrusted",
	Endpoint:      "Endpoint",
	AllowedIPs:    "AllowedIPs",
	Membership:    "Membership",
	DelegateTrust: "DelegateTrust",
}

func (l Level) String() string {
	s, ok := Names[l]
	if ok {
		return s
	}
	return strconv.Itoa(int(l))
}

// Evaluator is an interface for implementations that can answer whether
// a fact received from a remote source should be trusted and accepted into
// the set of locally known facts
type Evaluator interface {
	// TrustLevel evaluates the trust level that should be applied to a fact given its source,
	// returning nil if it doesn't have an opinion on the trust level
	TrustLevel(fact *fact.Fact, source net.UDPAddr) *Level
	// IsKnown checks whether the subject of a fact is already known to the local system,
	// or false if the peer is new.
	// TODO: IsKnown doesn't really belong here
	IsKnown(subject fact.Subject) bool
}

//go:generate go run github.com/vektra/mockery/cmd/mockery -testonly -inpkg -name Evaluator

// ShouldAccept checks whether a fact Attribute should be accepted, given the
// trust level of the source, and whether the peer is already locally
// configured
func ShouldAccept(attr fact.Attribute, known bool, level *Level) bool {
	if level == nil {
		// no trust evaluator gave an opinion, treat as Untrusted
		return false
	}
	// default threshold is effectively infinite, to be safe
	//nolint:ineffassign // safety catch for future code
	threshold := DelegateTrust
	switch attr {
	case fact.AttributeUnknown:
		// these are just "ping" packets, we should never store or relay them
		// we only keep track of who has sent us one
		return false
	case fact.AttributeEndpointV4, fact.AttributeEndpointV6:
		threshold = Endpoint

	case fact.AttributeAllowedCidrV4, fact.AttributeAllowedCidrV6:
		threshold = AllowedIPs

	case fact.AttributeMember, fact.AttributeMemberMetadata:
		threshold = Membership

	default:
		// unknown attribute
		return false
	}
	// if the peer isn't known to us, then the threshold moves up
	if !known && threshold < Membership {
		threshold = Membership
	}
	return *level >= threshold
}

// Ptr is a helper, mostly for tests, to allow specifying a trust constant
// in a place where a pointer is required.
func Ptr(level Level) *Level {
	return &level
}
