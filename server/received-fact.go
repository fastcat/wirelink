package server

import (
	"fmt"
	"net"

	"github.com/fastcat/wirelink/fact"
)

type ReceivedFact struct {
	fact   *fact.Fact
	source net.IP
}

func (rf *ReceivedFact) String() string {
	return fmt.Sprintf("RF{%v <- %v}", rf.fact, rf.source)
}

var _ fmt.Stringer = &ReceivedFact{}
