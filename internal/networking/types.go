package networking

import (
	"context"
	"io"
	"net"
	"time"
)

// Environment represents the top level abstraction of the system's networking
// environment.
type Environment interface {
	io.Closer
	// Interfaces is typically a wrapper for net.Interfaces()
	Interfaces() ([]Interface, error)
	// InterfaceByName looks up an interface by its name
	InterfaceByName(string) (Interface, error)

	// ListenUDP abstracts net.ListenUDP
	ListenUDP(network string, laddr *net.UDPAddr) (UDPConn, error)
}

// Interface represents a single network interface
type Interface interface {
	Name() string
	IsUp() bool
	Addrs() ([]net.IPNet, error)
	AddAddr(net.IPNet) error
}

// UDPConn abstracts net.UDPConn
type UDPConn interface {
	io.Closer

	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error

	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(p []byte, addr *net.UDPAddr) (n int, err error)

	// ReadPackets reads packets from the connection until it is either closed,
	// or the passed context is cancelled.
	// Packets or errors (other than the connection being closed) will be sent
	// to the output channel, which will be closed when this routine finishes.
	// Closing the connection is always the responsibility of the caller.
	ReadPackets(
		ctx context.Context,
		maxSize int,
		output chan<- *UDPPacket,
	) error
}

// UDPPacket represents a single result from ReadFromUDP, wrapped in a struct
// so that it can be sent on a channel.
type UDPPacket struct {
	Time time.Time
	Data []byte
	Addr *net.UDPAddr
	Err  error
}
