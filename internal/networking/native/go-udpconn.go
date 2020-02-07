package native

import (
	"net"

	"github.com/fastcat/wirelink/internal/networking"
)

// GoUDPConn implements networking.UDPConn by wrapping net.UDPConn
type GoUDPConn struct {
	net.UDPConn
}

// GoUDPConn implements networking.UDPConn
var _ networking.UDPConn = &GoUDPConn{}
