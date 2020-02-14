package vnet

import "net"

// A Socket represents a listening UDP socket which can send and receive
// Packets
type Socket struct {
	// TODO: this needs a mutex, but locking order gets gnarly
	iface   Interface
	addr    *net.UDPAddr
	inbound chan *Packet
	// TODO: encapsulation flag to filter allowed packet kinds
}

// InboundPacket enqueues a packet for the receive listener to process
func (s *Socket) InboundPacket(p *Packet) {
	s.inbound <- p
}

// OutboundPacket sends a packet out the socket's interface
func (s *Socket) OutboundPacket(p *Packet) {
	if s.iface != nil {
		s.iface.OutboundPacket(p)
	}
	// TODO: else error
}

// Close shuts down a socket
func (s *Socket) Close() {
	s.iface.DelSocket(s)
	s.iface = nil
	close(s.inbound)
}
