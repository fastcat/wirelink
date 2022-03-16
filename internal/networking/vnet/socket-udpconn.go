package vnet

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/util"
)

// socketUDPConn adapts a virtual socket to use as a UDPConn
type socketUDPConn struct {
	s       *Socket
	inbound chan *Packet
}

var _ networking.UDPConn = &socketUDPConn{}

// Connect creates a SocketUDPConn wrapper for the Socket to treat it as a
// networking.UDPConn.
func (s *Socket) Connect() networking.UDPConn {
	ret := &socketUDPConn{
		s: s,
		// make this reasonably deep to avoid accidental deadlocks
		inbound: make(chan *Packet, 10),
	}
	rx := func(p *Packet) bool {
		// TODO: can't find a way to avoid data races on the channel without
		// including the send in the mutex
		s.m.Lock()
		if ret.inbound == nil || s.rx == nil {
			// closed
			s.m.Unlock()
			return false
		}
		ret.inbound <- p
		s.m.Unlock()
		return true
	}
	s.m.Lock()
	s.rx = rx
	s.m.Unlock()
	return ret
}

// Close implements UDPConn
func (sc *socketUDPConn) Close() error {
	if sc.s == nil {
		return &net.OpError{
			Op:  "close",
			Err: errors.New("attempting to close closed socket"),
		}
	}
	sc.s.m.Lock()
	// Socket.Close will remove the rx handler, but there might still be outstanding calls to it
	sc.s._close()
	if sc.inbound != nil {
		// TODO: this might still occasionally data-race with the rx handler in Connect
		close(sc.inbound)
		sc.inbound = nil
	}
	sc.s.m.Unlock()
	sc.s = nil
	return nil
}

// SetReadDeadline implements UDPConn
func (sc *socketUDPConn) SetReadDeadline(t time.Time) error {
	panic("Not implemented")
}

// SetWriteDeadline implements UDPConn by always returning nil
func (sc *socketUDPConn) SetWriteDeadline(t time.Time) error {
	// this is a no-op as our sends are functionally instantaneous
	return nil
}

// ReadFromUDP implements UDPConn
func (sc *socketUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	// TODO: support deadline
	sc.s.m.Lock()
	inbound := sc.inbound
	sc.s.m.Unlock()
	if inbound == nil {
		err = net.ErrClosed
		return
	}
	p := <-sc.inbound
	n = copy(b, p.data)
	addr = p.src
	err = nil
	return
}

// WriteToUDP implements UDPConn
func (sc *socketUDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (n int, err error) {
	// make copies of addrs to ensure they don't change along the way
	dest := *addr
	src := *sc.s.addr
	// clear the Zone on the src, that isn't applicable to outbound packets
	src.Zone = ""
	packet := &Packet{
		src:  &src,
		dest: &dest,
		data: util.CloneBytes(p),
	}
	sent := sc.s.OutboundPacket(packet)
	if sent {
		return len(p), nil
	}
	// TODO: dropped / un-routable packets shouldn't be an error
	return 0, &net.OpError{
		Op:     "write",
		Addr:   addr,
		Source: packet.src,
		Err:    errors.New("no recipient for packet"),
	}
}

// ReadPackets implements UDPConn
func (sc *socketUDPConn) ReadPackets(
	ctx context.Context,
	maxSize int,
	output chan<- *networking.UDPPacket,
) error {
	done := ctx.Done()
	defer close(output)
	for {
		select {
		case <-done:
			return nil
		case p, ok := <-sc.inbound:
			if !ok {
				// closed
				return nil
			}
			output <- &networking.UDPPacket{
				Time: time.Now(),
				Addr: p.src,
				Data: p.data,
			}
		}
	}
}
