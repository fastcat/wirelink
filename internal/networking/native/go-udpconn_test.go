package native

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoUDPConn_ReadPackets(t *testing.T) {
	now := time.Now()

	type args struct {
		maxSize int

		send        []*networking.UDPPacket
		wantReceive []*networking.UDPPacket
	}
	tests := []struct {
		name      string
		args      args
		assertion require.ErrorAssertionFunc

		long bool
	}{
		{
			"empty",
			args{
				-1,
				[]*networking.UDPPacket{},
				[]*networking.UDPPacket{},
			},
			require.NoError,
			false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.long && testing.Short() {
				t.SkipNow()
			}

			if tt.args.maxSize < 0 {
				tt.args.maxSize = 0
				for _, p := range tt.args.send {
					if len(p.Data) > tt.args.maxSize {
						tt.args.maxSize = len(p.Data)
					}
				}
			}

			// pick a random high port, pray we can open it for listening
			e := &GoEnvironment{}
			recvAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 32768 + rand.Intn(32768)}
			udpRecv, err := e.ListenUDP("udp", recvAddr)
			require.NoError(t, err)
			// make another socket to send to this one
			// FIXME: shouldn't need to make a listen socket to send, but abstraction is missing this
			sendAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 32768 + rand.Intn(32768)}
			udpSend, err := e.ListenUDP("udp", sendAddr)
			require.NoError(t, err)

			sendDone := make(chan struct{})
			recvDone := make(chan struct{})

			ctx := context.Background()
			receiveChan := make(chan *networking.UDPPacket, len(tt.args.send)+len(tt.args.wantReceive))

			// have to run the test code async to be concurrent with the sending
			var gotErr error
			go func() {
				defer close(recvDone)
				gotErr = udpRecv.ReadPackets(ctx, tt.args.maxSize, receiveChan)
			}()
			// start the sender
			go func() {
				defer close(sendDone)
				// FIXME: share this with mock UDPConn.WithPacketSequence
				// this one is much simpler due to not watching a Context
				offset := time.Now().Sub(now)
				for i := range tt.args.send {
					packetDeadline := tt.args.send[i].Time.Add(offset)
					timer := time.NewTimer(time.Now().Sub(packetDeadline))
					<-timer.C
					udpSend.WriteToUDP(tt.args.send[i].Data, recvAddr)
				}
			}()

			// wait for completion
			<-sendDone
			// close the socket so the receiver knows to stop
			// TODO: support ctx mode too
			require.NoError(t, udpRecv.Close())
			<-recvDone

			tt.assertion(t, gotErr)

			gotReceive := make([]*networking.UDPPacket, 0, len(tt.args.wantReceive))
			for p := range receiveChan {
				gotReceive = append(gotReceive, p)
			}
			// FIXME: this is going to fail on timestamps
			assert.Equal(t, tt.args.wantReceive, gotReceive)
		})
	}
}
