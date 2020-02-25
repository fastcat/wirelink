package vnet

import (
	"sync"
)

// A Network represents a connected region within which packets can pass among
// Interfaces
type Network struct {
	m          *sync.Mutex
	id         string
	world      *World
	interfaces map[string]*PhysicalInterface
}

// EnqueuePacket enqueues a packet to deliver to the network
func (n *Network) EnqueuePacket(p *Packet) bool {
	n.m.Lock()
	var dest *PhysicalInterface
	for _, i := range n.interfaces {
		if destinationAddrMatch(p, i.addrs) {
			dest = i
			break
		}
	}
	n.m.Unlock()
	if dest == nil {
		return false
	}
	return dest.InboundPacket(p)
}
