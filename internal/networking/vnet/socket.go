package vnet

import (
	"net"
)

// A Socket represents a listening UDP socket which can send and receive
// Packets
type Socket struct {
	// TODO: this needs a mutex, but locking order gets gnarly
	sender SocketOwner
	addr   *net.UDPAddr
	rx     func(*Packet) bool
	// TODO: encapsulation flag to filter allowed packet kinds
}

// InboundPacket enqueues a packet for the receive listener to process
func (s *Socket) InboundPacket(p *Packet) bool {
	rx := s.rx
	if rx == nil {
		return false
	}
	return rx(p)
}

// OutboundPacket sends a packet out the socket's interface
func (s *Socket) OutboundPacket(p *Packet) bool {
	if s.sender != nil {
		return s.sender.OutboundPacket(p)
	}
	return false
}

// Close shuts down a socket
func (s *Socket) Close() {
	if s.sender != nil {
		s.sender.DelSocket(s)
		s.sender = nil
	}
	s.rx = nil
}

// Connect creates a SocketUDPConn wrapper for the Socket to treat it as a
// networking.UDPConn.
func (s *Socket) Connect() *SocketUDPConn {
	ret := &SocketUDPConn{
		s:       s,
		inbound: make(chan *Packet, 1),
	}
	s.rx = func(p *Packet) bool {
		ret.inbound <- p
		return true
	}
	return ret
}
