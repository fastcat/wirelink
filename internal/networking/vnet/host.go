package vnet

import (
	"fmt"
	"net"
	"sync"
)

// A Host represents a system in a World with some set (possibly empty) of
// Interfaces, which may be connected to Networks to send and receive packets.
type Host struct {
	m          *sync.Mutex
	id         string
	world      *World
	interfaces map[string]Interface

	// host sockets are not listening on any specific interface
	sockets map[string]*Socket
}

func (h *Host) createBaseIface(name string) *BaseInterface {
	return &BaseInterface{
		m:       &sync.Mutex{},
		id:      fmt.Sprintf("%s:%s", h.id, name),
		name:    name,
		world:   h.world,
		host:    h,
		addrs:   map[string]net.IPNet{},
		sockets: map[string]*Socket{},
	}
	// caller has to fill in self
}

// AddPhy adds a new interface to the Host with the given name,
// assigning it an id combining the host id with the name to ensure uniqueness
func (h *Host) AddPhy(name string) *PhysicalInterface {
	h.m.Lock()
	defer h.m.Unlock()
	// TODO: validate id is unique
	ret := &PhysicalInterface{
		BaseInterface: *h.createBaseIface(name),
		network:       nil,
	}
	ret.self = ret
	h.interfaces[name] = ret
	return ret
}

// AddTun creates a new tunnel interface on the host, but does not connect it
// to any peers, nor open a listen port for it to receive packets
func (h *Host) AddTun(name string) *Tunnel {
	h.m.Lock()
	defer h.m.Unlock()

	ret := &Tunnel{
		BaseInterface: *h.createBaseIface(name),
		upstream:      nil,
		peers:         map[string]*TunPeer{},
	}
	ret.self = ret
	h.interfaces[name] = ret
	return ret
}

// DelInterface unregisters an interface from the host and detaches it from
// any network
func (h *Host) DelInterface(name string) Interface {
	h.m.Lock()
	i := h.interfaces[name]
	delete(h.interfaces, name)
	h.m.Unlock()
	i.DetachFromNetwork()
	return i
}

// AddSocket creates a new socket on the interface
func (h *Host) AddSocket(a *net.UDPAddr) *Socket {
	ret := &Socket{
		m:      &sync.Mutex{},
		sender: h,
		addr:   a,
	}
	h.m.Lock()
	// TODO: validate addr is unique-ish
	h.sockets[a.String()] = ret
	h.m.Unlock()
	// TODO: goroutines to process packets
	return ret
}

// DelSocket unregisters a socket from the interface
func (h *Host) DelSocket(s *Socket) {
	h.m.Lock()
	defer h.m.Unlock()
	// TODO: verify socket matches map entry
	delete(h.sockets, s.addr.String())
}

// InboundPacket inspects the packet to see if its destination matches any
// host-level listening socket, and if so enqueues it for that listener
func (h *Host) InboundPacket(p *Packet) bool {
	h.m.Lock()
	var rs *Socket
	rs = destinationSocket(p, h.sockets)
	h.m.Unlock()

	if rs == nil {
		return false
	}
	return rs.InboundPacket(p)
}

// OutboundPacket tries to send a packet on each interface registered on the host
func (h *Host) OutboundPacket(p *Packet) bool {
	// FIXME: this is a deadlock risk
	h.m.Lock()
	for _, iface := range h.interfaces {
		if iface.OutboundPacket(p) {
			h.m.Unlock()
			return true
		}
	}
	h.m.Unlock()

	return false
}
