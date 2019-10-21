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
	Untrusted Level = iota
	// Endpoint means we should trust it enough to try endpoints we may have received
	Endpoint
	// AllowedIPs means we should trust it enough to add AllowedIPs to our local
	// configuration for the peer, if we can make a direct connection to it
	AllowedIPs
	// AddPeer means we should trust it enough to add it as a new peer in the
	// local configuration if we don't have it
	AddPeer
	// DelPeer means that that we trust it enough to remove any peers it doesn't
	// tell us exist (assuming it's online, and no other AddPeer contradicts it)
	DelPeer
	// SetTrust means a peer is trusted to tell us the trust level of other peers
	SetTrust
)

// Values is a handy map to ease parsing strings to trust levels.
// FIXME: this is mutable, golang doesn't allow const/immutable maps
var Values map[string]Level = map[string]Level{
	"Untrusted":  Untrusted,
	"Endpoint":   Endpoint,
	"AllowedIPs": AllowedIPs,
	"AddPeer":    AddPeer,
	"DelPeer":    DelPeer,
	"SetTrust":   SetTrust,
}

// Names is a handy map to ease stringifying trust levels.
// FIXME: this is mutable, golang doesn't allow const/immutable maps
var Names map[Level]string = map[Level]string{
	Untrusted:  "Untrusted",
	Endpoint:   "Endpoint",
	AllowedIPs: "AllowedIPs",
	AddPeer:    "AddPeer",
	DelPeer:    "DelPeer",
	SetTrust:   "SetTrust",
}

func (l Level) String() string {
	s, ok := Names[l]
	if ok {
		return s
	}
	return string(l)
}

// Evaluator is an interface for implementations that can answer whether
// a fact received from a remote source should be trusted and accepted into
// the set of locally known facts
type Evaluator interface {
	// TrustLevel evaluates the trust level that should be applied to a fact given its source,
	// returning nil if it doesn't have an opinion on the trust level
	TrustLevel(fact *fact.Fact, source net.IP) *Level
	// IsKnown checks whether the subject of a fact is already known to the local system,
	// or false if the peer is new.
	// TODO: IsKnown doesn't really belong here
	IsKnown(subject fact.Subject) bool
}

// ShouldAccept checks whether a fact Atribute should be accepted at a given trust level
func ShouldAccept(attr fact.Attribute, known bool, level *Level) bool {
	if level == nil {
		// no trust evaluator gave an opinion, treat as Untrusted
		return false
	}
	// default threshold is effectively infinite, to be safe
	threshold := SetTrust
	switch attr {
	case fact.AttributeUnknown:
		// these are just "ping" packets, we should never store or relay them
		// we only keep track of who has sent us one
		return false
	case fact.AttributeEndpointV4:
		fallthrough
	case fact.AttributeEndpointV6:
		threshold = Endpoint

	case fact.AttributeAllowedCidrV4:
		fallthrough
	case fact.AttributeAllowedCidrV6:
		threshold = AllowedIPs
	default:
		// unknown attribute
		return false
	}
	// if the peer isn't known to us, then the threshold moves up
	if !known && threshold < AddPeer {
		threshold = AddPeer
	}
	return *level >= threshold
}
