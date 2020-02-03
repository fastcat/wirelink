package mocks

import (
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal/networking"
)

const tdInterfaces = "_Interfaces"

// WithInterface updates the mock environment to be aware of a new interface name
func (m *Environment) WithInterface(name string) *Interface {
	iface := &Interface{}
	td := m.TestData()
	if td.Has(tdInterfaces) {
		td.Set(tdInterfaces, append(td.Get(tdInterfaces).MustInterSlice(), iface))
	} else {
		td.Set(tdInterfaces, []interface{}{iface})
	}
	m.On("InterfaceByName", name).Return(iface, nil)
	return iface
}

// WithKnownInterfaces sets m.Interfaces() to return all the interface mocks
// set up via WithInterfaces (now or in the future)
func (m *Environment) WithKnownInterfaces() {
	// this relies on the mockery return function support
	m.On("Interfaces").Return(
		func() []networking.Interface {
			tdi := m.TestData().Get(tdInterfaces)
			if tdi == nil || tdi.IsNil() {
				return nil
			}
			ifaces := tdi.MustInterSlice()
			ret := make([]networking.Interface, len(ifaces))
			for i := range ifaces {
				ret[i] = ifaces[i].(networking.Interface)
			}
			return ret
		},
		nil,
	)
}

// WithAddrs mocks the interface to return the given address list
func (i *Interface) WithAddrs(addrs []net.IPNet) {
	i.On("Addrs", addrs, nil)
}

// WithSimpleInterfaces sets up a simple map of interface name to ip address
func (m *Environment) WithSimpleInterfaces(ifaces map[string]net.IPNet) map[string]*Interface {
	ret := make(map[string]*Interface, len(ifaces))
	for n, ipn := range ifaces {
		iface := m.WithInterface(n)
		iface.WithAddrs([]net.IPNet{ipn})
		ret[n] = iface
	}
	return ret
}

// Test sets the T used on the Environment and all its registered Interfaces
func (m *Environment) Test(t *testing.T) {
	m.Mock.Test(t)
	if m.TestData().Has(tdInterfaces) {
		for _, iface := range m.TestData().Get(tdInterfaces).MustInterSlice() {
			iface.(*Interface).Test(t)
		}
	}
}
