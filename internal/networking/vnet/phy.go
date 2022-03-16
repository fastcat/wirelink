package vnet

import (
	"net"
)

// An PhysicalInterface represents a network interface on a Host that is part of
// some World. The interface may be attached and detached from various Networks
// in the World.
type PhysicalInterface struct {
	BaseInterface
	network *Network
}

var _ Interface = &PhysicalInterface{}

// DetachFromNetwork disconnects the interface from its network, if any.
func (i *PhysicalInterface) DetachFromNetwork() {
	i.m.Lock()
	defer i.m.Unlock()
	if i.network == nil {
		return
	}
	i.network.m.Lock()
	defer i.network.m.Unlock()
	delete(i.network.interfaces, i.id)
	i.network = nil
}

// AttachToNetwork connects this interface to a given network,
// allowing it to send packets to other hosts on the network
func (i *PhysicalInterface) AttachToNetwork(n *Network) {
	i.DetachFromNetwork()

	i.m.Lock()
	defer i.m.Unlock()
	n.m.Lock()
	defer n.m.Unlock()
	// TODO: validate network is from the same world
	i.network = n
	n.interfaces[i.id] = i
}

// OutboundPacket enqueues the packet to be sent out the interface into the
// network, if possible
func (i *PhysicalInterface) OutboundPacket(p *Packet) bool {
	i.m.Lock()
	// we assume connectivity based on the network, don't really care about ip subnets
	if !destinationSubnetMatch(p, i.addrs) {
		i.m.Unlock()
		return false
	}
	// TODO: bogon detection (src addr match)?
	n := i.network
	if n == nil {
		i.m.Unlock()
		return false
	}

	// fixup source addr
	if n != nil && (p.src.IP.Equal(net.IPv4zero) || p.src.IP.Equal(net.IPv6zero)) {
		// TODO: makes assumptions about multiple addrs on interface
		for _, addr := range i.addrs {
			p.src.IP = addr.IP
			break
		}
	}

	i.m.Unlock()

	return n.EnqueuePacket(p)
}
