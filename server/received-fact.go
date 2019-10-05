package server

import (
	"fmt"
	"net"

	"github.com/fastcat/wirelink/fact"
)

// ReceivedFact is a tuple of a fact and its source.
// It is used for the queue of parsed packets received over the network,
// to hold them in a batch before evaluating them for acceptance
type ReceivedFact struct {
	fact   *fact.Fact
	source net.IP
}

func (rf *ReceivedFact) String() string {
	return fmt.Sprintf("RF{%v <- %v}", rf.fact, rf.source)
}

var _ fmt.Stringer = &ReceivedFact{}
