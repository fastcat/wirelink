// Package mocks provides mock implementations of the networking apis,
// for the testify mock library, generated via go generate and mockery.
package mocks

//go:generate mockery -dir ../ -output ./ -name "Environment|Interface|UDPConn"

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/internal/networking"

	"github.com/stretchr/testify/mock"
)

const tdInterfaces = "_Interfaces"
const tdConnections = "_Connections"

// WithInterface updates the mock environment to be aware of a new interface name
func (_m *Environment) WithInterface(name string) *Interface {
	iface := &Interface{}
	td := _m.TestData()
	if td.Has(tdInterfaces) {
		td.Set(tdInterfaces, append(td.Get(tdInterfaces).MustInterSlice(), iface))
	} else {
		td.Set(tdInterfaces, []interface{}{iface})
	}
	_m.On("InterfaceByName", name).Return(iface, nil).Maybe()
	iface.On("Name").Return(name).Maybe()
	iface.On("IsUp").Return(true).Maybe()
	return iface
}

// WithKnownInterfaces sets m.Interfaces() to return all the interface mocks
// set up via WithInterfaces (now or in the future)
func (_m *Environment) WithKnownInterfaces() {
	// this relies on the mockery return function support
	_m.On("Interfaces").Return(
		func() []networking.Interface {
			tdi := _m.TestData().Get(tdInterfaces)
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
func (i *Interface) WithAddrs(addrs ...net.IPNet) {
	i.On("Addrs").Return(addrs, nil).Maybe()
}

// WithSimpleInterfaces sets up a simple map of interface name to ip address
func (_m *Environment) WithSimpleInterfaces(ifaces map[string]net.IPNet) map[string]*Interface {
	ret := make(map[string]*Interface, len(ifaces))
	for n, ipn := range ifaces {
		iface := _m.WithInterface(n)
		iface.WithAddrs(ipn)
		ret[n] = iface
	}
	return ret
}

// Test sets the T used on the Environment and all its registered Interfaces
func (_m *Environment) Test(t *testing.T) {
	_m.Mock.Test(t)
	if _m.TestData().Has(tdInterfaces) {
		for _, iface := range _m.TestData().Get(tdInterfaces).MustInterSlice() {
			iface.(*Interface).Test(t)
		}
	}
	if _m.TestData().Has(tdConnections) {
		for _, iface := range _m.TestData().Get(tdConnections).MustInterSlice() {
			iface.(*UDPConn).Test(t)
		}
	}
}

// AssertExpectations calls the method on the Environment mock and on all its
// registered Interface mocks
func (_m *Environment) AssertExpectations(t *testing.T) {
	_m.Mock.AssertExpectations(t)
	if _m.TestData().Has(tdInterfaces) {
		for _, iface := range _m.TestData().Get(tdInterfaces).MustInterSlice() {
			iface.(*Interface).AssertExpectations(t)
		}
	}
	if _m.TestData().Has(tdConnections) {
		for _, iface := range _m.TestData().Get(tdConnections).MustInterSlice() {
			iface.(*UDPConn).AssertExpectations(t)
		}
	}
}

// RegisterUDPConn records a mocked connection as being related to the environment,
// so that calling Test or AssertExpections will propagate to it
func (_m *Environment) RegisterUDPConn(c *UDPConn) *UDPConn {
	td := _m.TestData()
	if td.Has(tdConnections) {
		td.Set(tdConnections, append(td.Get(tdConnections).MustInterSlice(), c))
	} else {
		td.Set(tdConnections, []interface{}{c})
	}
	return c
}

// WithPacketSequence will mock the connection to emit the given packet sequence
// at their denoted times, interpreted as offsets relative to reference,
// relative to when ReadPackets is called. It will obey the context parameter
// and stop sending early if it is canceled.
func (c *UDPConn) WithPacketSequence(reference time.Time, packets ...*networking.UDPPacket) *mock.Call {
	return c.On(
		"ReadPackets",
		// we don't actually care about the arg values, we're going to use them, not check them
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(func(ctx context.Context, maxSize int, output chan<- *networking.UDPPacket) error {
		defer close(output)
		offset := time.Since(reference)
		ctxDone := ctx.Done()
		for i := range packets {
			packetDeadline := packets[i].Time.Add(offset)
			timer := time.NewTimer(time.Since(packetDeadline))
			select {
			case <-ctxDone:
				if !timer.Stop() {
					<-timer.C
				}
				// NOTE: the real packet reader returns nil here
				return ctx.Err()
			case <-timer.C:
				output <- packets[i]
			}
		}
		return nil
	})
}
