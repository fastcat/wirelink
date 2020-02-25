package vnet

import (
	"net"

	"github.com/fastcat/wirelink/internal/networking"
)

type wrappedPhy struct {
	i *PhysicalInterface
}

// Wrap implements Interface
func (i *PhysicalInterface) Wrap() networking.Interface {
	return &wrappedPhy{i}
}

// Name implements Interface
func (i *wrappedPhy) Name() string {
	i.i.m.Lock()
	defer i.i.m.Unlock()
	return i.i.name
}

// IsUp implements interface
func (i *wrappedPhy) IsUp() bool {
	i.i.m.Lock()
	defer i.i.m.Unlock()
	return i.i.network != nil
}

// Addrs implements Interface
func (i *wrappedPhy) Addrs() ([]net.IPNet, error) {
	i.i.m.Lock()
	defer i.i.m.Unlock()
	ret := make([]net.IPNet, 0, len(i.i.addrs))
	for _, a := range i.i.addrs {
		ret = append(ret, a)
	}
	return ret, nil
}

// AddAddr implements Interface
func (i *wrappedPhy) AddAddr(addr net.IPNet) error {
	i.i.AddAddr(addr)
	return nil
}

type wrappedTun struct {
	t *Tunnel
}

// Wrap implements Interface
func (t *Tunnel) Wrap() networking.Interface {
	return &wrappedTun{t}
}

// Name implements Interface
func (t *wrappedTun) Name() string {
	t.t.m.Lock()
	defer t.t.m.Unlock()
	return t.t.name
}

// IsUp implements interface
func (t *wrappedTun) IsUp() bool {
	t.t.m.Lock()
	defer t.t.m.Unlock()
	return t.t.upstream != nil
}

// Addrs implements Interface
func (t *wrappedTun) Addrs() ([]net.IPNet, error) {
	t.t.m.Lock()
	defer t.t.m.Unlock()
	ret := make([]net.IPNet, 0, len(t.t.addrs))
	for _, a := range t.t.addrs {
		ret = append(ret, a)
	}
	return ret, nil
}

// AddAddr implements Interface
func (t *wrappedTun) AddAddr(addr net.IPNet) error {
	t.t.AddAddr(addr)
	return nil
}
