// Package native provdies common base implementations of the
// networking.Environment and related interfaces, or at least the portions that
// can be implemented using common native Go APIs.
package native

import (
	"net"

	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/networking"

	"golang.zx2c4.com/wireguard/wgctrl"
)

// GoEnvironment is a partial implementation of Environment which provides the
// methods and types that the go runtime can answer
type GoEnvironment struct {
}

// GoEnvironment does not fully implement Environment
// var _ networking.Environment = &GoEnvironment{}

// Interfaces implements Environment
func (e *GoEnvironment) Interfaces() ([]*GoInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ret := make([]*GoInterface, len(ifaces))
	for i, iface := range ifaces {
		ret[i] = &GoInterface{iface}
	}

	return ret, nil
}

// InterfaceByName implements Environment by wrapping net.InterfaceByName
func (e *GoEnvironment) InterfaceByName(name string) (*GoInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return &GoInterface{*iface}, nil
}

// ListenUDP implements Environment by wrapping net.ListenUDP
func (e *GoEnvironment) ListenUDP(network string, laddr *net.UDPAddr) (networking.UDPConn, error) {
	conn, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	return &GoUDPConn{*conn}, nil
}

// NewWgClient implements Environment by wrapping wgctrl.New()
func (e *GoEnvironment) NewWgClient() (internal.WgClient, error) {
	return wgctrl.New()
}
