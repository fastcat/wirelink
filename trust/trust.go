package trust

import (
	"net"

	"github.com/fastcat/wirelink/fact"
)

type TrustEvaluator interface {
	IsTrusted(fact *fact.Fact, source net.IP) bool
}
