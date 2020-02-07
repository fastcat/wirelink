package networking

import (
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
}
