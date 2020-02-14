package vnet

import (
	"net"
	"sync"
)

// A World represents a global set of networks, hosts, and their interfaces.
type World struct {
	m        *sync.Mutex
	networks map[string]*Network
	hosts    map[string]*Host
}

// NewWorld initializes a new empty world to which hosts and networks can be
// added.
func NewWorld() *World {
	ret := &World{
		m:        &sync.Mutex{},
		networks: map[string]*Network{},
		hosts:    map[string]*Host{},
	}
	return ret
}

// CreateNetwork creates and attaches a new Network with the given id to the
// world
func (w *World) CreateNetwork(id string) *Network {
	w.m.Lock()
	defer w.m.Unlock()
	// TODO: validate id is unique
	ret := &Network{
		m:          &sync.Mutex{},
		id:         id,
		world:      w,
		interfaces: map[string]*PhysicalInterface{},
	}
	// TODO: more network initialization
	w.networks[id] = ret
	return ret
}

// CreateEmptyHost creates a new Host within the world, with no interfaces
func (w *World) CreateEmptyHost(id string) *Host {
	w.m.Lock()
	defer w.m.Unlock()
	// TODO: validate id is unique
	ret := &Host{
		m:          &sync.Mutex{},
		id:         id,
		world:      w,
		interfaces: map[string]Interface{},
	}
	// TODO: more host initialization
	w.hosts[id] = ret
	return ret
}

// CreateHost creates a simple host within the world, with its 'lo' (localhost)
// interface pre-configured
func (w *World) CreateHost(id string) *Host {
	h := w.CreateEmptyHost(id)
	n := h.AddPhy("lo")
	n.AddAddr(net.IPNet{
		IP:   net.IPv4(127, 0, 0, 1),
		Mask: net.CIDRMask(8, 32),
	})
	n.AddAddr(net.IPNet{
		IP:   net.IPv6loopback,
		Mask: net.CIDRMask(128, 128),
	})
	return h
}
