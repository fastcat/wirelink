package server

import (
	"net"

	"github.com/fastcat/wirelink/fact"
)

type ReceivedFact struct {
	fact   *fact.Fact
	source net.IP
}
