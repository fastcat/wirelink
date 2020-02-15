package vnet

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/fastcat/wirelink/internal/networking"
)

// SocketUDPConn adapts a virtual socket to use as a UDPConn
type SocketUDPConn struct {
	s       *Socket
	inbound chan *Packet
}

var _ networking.UDPConn = &SocketUDPConn{}

// Close implements UDPConn
func (sc *SocketUDPConn) Close() error {
	if sc.s == nil {
		return &net.OpError{
			Op:  "close",
			Err: errors.New("Attempting to close closed socket"),
		}
	}
	sc.s.Close()
	// TODO: this is a panic risk -- might be an rx instance running about to send on this channel
	close(sc.inbound)
	return nil
}

// SetReadDeadline implements UDPConn
func (sc *SocketUDPConn) SetReadDeadline(t time.Time) error {
	panic("Not implemented")
}

// SetWriteDeadline implements UDPConn
func (sc *SocketUDPConn) SetWriteDeadline(t time.Time) error {
	panic("Not implemented")
}

// ReadFromUDP implements UDPConn
func (sc *SocketUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	// TODO: support deadline
	p := <-sc.inbound
	n = copy(b, p.data)
	addr = p.src
	err = nil
	return
}

// WriteToUDP implements UDPConn
func (sc *SocketUDPConn) WriteToUDP(p []byte, addr *net.UDPAddr) (n int, err error) {
	packet := &Packet{
		src:  sc.s.addr,
		dest: addr,
		data: cloneBytes(p),
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
func (sc *SocketUDPConn) ReadPackets(
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
