package vnet

import (
	"net"
	"sync"
)

// A Socket represents a listening UDP socket which can send and receive
// Packets
type Socket struct {
	m      *sync.Mutex
	sender SocketOwner
	addr   *net.UDPAddr
	rx     func(*Packet) bool
	// TODO: encapsulation flag to filter allowed packet kinds
}

// InboundPacket enqueues a packet for the receive listener to process
func (s *Socket) InboundPacket(p *Packet) bool {
	s.m.Lock()
	rx := s.rx
	s.m.Unlock()

	if rx == nil {
		return false
	}
	return rx(p)
}

// OutboundPacket sends a packet out the socket's interface
func (s *Socket) OutboundPacket(p *Packet) bool {
	s.m.Lock()
	sender := s.sender
	s.m.Unlock()
	if sender != nil {
		return sender.OutboundPacket(p)
	}
	return false
}

// Close shuts down a socket
func (s *Socket) Close() {
	s.m.Lock()
	defer s.m.Unlock()
	if s.sender != nil {
		s.sender.DelSocket(s)
		s.sender = nil
	}
	s.rx = nil
}
