package vnet

import (
	"net"
	"sync"
)

// An Interface is any network interface, whether physical or virtual, attached
// to a Host, which can be used to send and receive Packets.
type Interface interface {
	DetachFromNetwork()
	OutboundPacket(*Packet)
	DelSocket(*Socket)
}

// BaseInterface handles the common elements of both physical and tunnel
// Interfaces
type BaseInterface struct {
	m       *sync.Mutex
	id      string
	name    string
	world   *World
	host    *Host
	addrs   map[string]net.IPNet
	sockets map[string]*Socket
	self    Interface
}

// AddAddr adds an IP address to the interface on which it can receive packets
// and from which it can send them
func (i *BaseInterface) AddAddr(a net.IPNet) {
	i.m.Lock()
	defer i.m.Unlock()
	// TODO: clone address so caller can't break it
	i.addrs[a.String()] = a
}

// AddSocket creates a new socket on the interface
func (i *BaseInterface) AddSocket(a *net.UDPAddr) *Socket {
	ret := &Socket{
		iface:   i.self,
		addr:    a,
		inbound: make(chan *Packet),
	}
	i.m.Lock()
	// TODO: validate addr is unique-ish
	i.sockets[a.String()] = ret
	i.m.Unlock()
	// TODO: goroutines to process packets
	return ret
}

// DelSocket unregisters a socket from the interface
func (i *BaseInterface) DelSocket(s *Socket) {
	i.m.Lock()
	defer i.m.Unlock()
	// TODO: verify socket matches map entry
	delete(i.sockets, s.addr.String())
}

// InboundPacket inspects the packet to see if its destination matches any
// address on the interface and any listening socket, and if so enqueues it
// for that listener
func (i *BaseInterface) InboundPacket(p *Packet) {
	i.m.Lock()
	var rs *Socket
FIND_RS:
	for _, a := range i.addrs {
		am := a.IP.Mask(a.Mask)
		pm := p.dest.IP.Mask(a.Mask)
		if !am.Equal(pm) {
			continue
		}
		for _, s := range i.sockets {
			if s.addr.Port != p.dest.Port {
				continue
			}
			if s.addr.IP.Equal(net.IPv4zero) || s.addr.IP.Equal(net.IPv6zero) || s.addr.IP.Equal(p.dest.IP) {
				// TODO: differentiate v4 and v6 any addresses here
				rs = s
				break FIND_RS
			}
		}
	}
	i.m.Unlock()
	if rs == nil {
		return
	}
	rs.InboundPacket(p)
}
