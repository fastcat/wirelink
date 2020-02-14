package vnet

import "sync"

// A Network represents a connected region within which packets can pass among
// Interfaces
type Network struct {
	m          *sync.Mutex
	id         string
	world      *World
	interfaces map[string]*PhysicalInterface
	packets    chan *Packet
}

// EnqueuePacket enqueues a packet to deliver to the network
func (n *Network) EnqueuePacket(p *Packet) {
	n.packets <- p
}
