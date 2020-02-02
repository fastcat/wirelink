package native

import (
	"net"
)

// GoEnvironment is a partial implementation of Environment which provides the
// methods and types that the go runtime can answer
type GoEnvironment struct {
}

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

// InterfaceByName implements Environment
func (e *GoEnvironment) InterfaceByName(name string) (*GoInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return &GoInterface{*iface}, nil
}

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
	ret := make([]net.IPNet, len(addrs))
	for i, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			ret[i] = *ipn
		} else {
			ip, ipn, err := net.ParseCIDR(a.String())
			if err != nil {
				return nil, err
			}
			// ParseCIDR uses the masked version of the ip in ipn, we want the unmasked one
			ret[i] = net.IPNet{IP: ip, Mask: ipn.Mask}
		}
	}
	return ret, nil
}
