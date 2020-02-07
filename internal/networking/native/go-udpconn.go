package native

import (
	"context"
	"net"
	"time"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/util"
)

// GoUDPConn implements networking.UDPConn by wrapping net.UDPConn
type GoUDPConn struct {
	net.UDPConn
}

// GoUDPConn implements networking.UDPConn
var _ networking.UDPConn = &GoUDPConn{}

// ReadPackets implements networking.UDPConn.
// TODO: the cancellation context won't be obeyed very well.
// Methodology loosely adapted from:
// https://medium.com/@zombiezen/canceling-i-o-in-go-capn-proto-5ae8c09c5b29
// via https://github.com/golang/go/issues/20280#issue-227074518
// UDP makes this simpler however as partial reads are not a concern
func (c *GoUDPConn) ReadPackets(
	ctx context.Context,
	maxSize int,
	packets chan<- *networking.UDPPacket,
) error {
	defer close(packets)

	ctxDone := ctx.Done()
	monitorDone := make(chan struct{})
	readsDone := make(chan struct{})
	buffer := make([]byte, maxSize)

	// start a goroutine to monitor the context channel, and interrupt the read
	// whenever it closes
	go func() {
		defer close(monitorDone)
		for {
			select {
			case <-ctxDone:
				// interrupt any ongoing read
				c.SetReadDeadline(time.Now())
				return
			case <-readsDone:
				return
			}
		}
	}()

READLOOP:
	for {
		select {
		case <-ctxDone:
			break READLOOP
		default:
			deadline, ok := ctx.Deadline()
			if ok {
				c.SetReadDeadline(deadline)
			} else {
				c.SetReadDeadline(time.Time{})
			}
			n, addr, err := c.ReadFromUDP(buffer)
			now := time.Now()

			if err != nil {
				if util.IsNetClosing(err) {
					// the socket has been closed, we're done
					break READLOOP
				}

				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// ignore timeouts, generally this is us poking ourselves
					continue
				}

				// else fall-through will send the error to the caller
			}

			var data []byte
			if n > 0 {
				data = make([]byte, n)
				copy(data, buffer[:n])
			}

			packets <- &networking.UDPPacket{
				Time: now,
				Addr: addr,
				Data: data,
				Err:  err,
			}
		}
	}

	close(readsDone)
	<-monitorDone

	// reset read deadline on the connection to be safe
	c.SetReadDeadline(time.Time{})

	return nil
}
