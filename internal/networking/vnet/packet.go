package vnet

import "net"

// A Packet represents a UDP packet traveling on the virtual network
type Packet struct {
	src, dest    *net.UDPAddr
	data         []byte
	encapsulated *Packet
}
