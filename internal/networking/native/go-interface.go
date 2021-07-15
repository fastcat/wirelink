package native

import (
	"net"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/log"
)

// GoInterface provides as much of Interface as the go runtime can
type GoInterface struct {
	net.Interface
}

// Name implements Interface, gets its name
func (i *GoInterface) Name() string {
	return i.Interface.Name
}

// IsUp implements Interface, checks for FlagUp
func (i *GoInterface) IsUp() bool {
	return i.Flags&net.FlagUp == net.FlagUp
}

// Addrs implements Interface, looks up the IP addresses for the interface
func (i *GoInterface) Addrs() ([]net.IPNet, error) {
	addrs, err := i.Interface.Addrs()
	if err != nil {
		return nil, err
	}
	ret := make([]net.IPNet, 0, len(addrs))
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			ret = append(ret, *ipn)
		} else {
			// this should never happen
			log.Error("Got a %T from interface.Addrs, not a net.IPNet", a)
		}
	}
	return ret, nil
}

// AddAddr implements Interface, returns ErrAddAddrUnsupported
func (i *GoInterface) AddAddr(net.IPNet) error {
	return networking.ErrAddAddrUnsupported
}

var _ networking.Interface = (*GoInterface)(nil)
