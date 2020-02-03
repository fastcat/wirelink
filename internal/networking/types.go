package networking

import (
	"io"
	"net"
)

// Environment represents the top level abstraction of the system's networking
// environment.
type Environment interface {
	io.Closer
	// Interfaces is typically a wrapper for net.Interfaces()
	Interfaces() ([]Interface, error)
	// InterfaceByName looks up an interface by its name
	InterfaceByName(string) (Interface, error)
}

// Interface represents a single network interface
type Interface interface {
	Name() string
	IsUp() bool
	Addrs() ([]net.IPNet, error)
	AddAddr(net.IPNet) error
}

// TODO: virtual udp sockets so we can write tests of server interactions
