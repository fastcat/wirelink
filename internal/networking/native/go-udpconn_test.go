package native

import (
	"context"
	"math/rand"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoUDPConn_ReadPackets(t *testing.T) {
	now := time.Now()
	packet1 := make([]byte, 1+rand.Intn(1400))
	packet2 := make([]byte, 1+rand.Intn(1400))
	testutils.MustRandBytes(t, packet1)

	type args struct {
		maxSize int

		send        []*networking.UDPPacket
		wantReceive []*networking.UDPPacket
	}
	tests := []struct {
		name      string
		args      args
		assertion require.ErrorAssertionFunc

		cancelCtx   bool
		closeSocket bool

		long bool
	}{
		{
			"empty via close",
			args{
				-1,
				[]*networking.UDPPacket{},
				[]*networking.UDPPacket{},
			},
			require.NoError,
			false, true,
			false,
		},
		{
			"empty via cancel",
			args{
				-1,
				[]*networking.UDPPacket{},
				[]*networking.UDPPacket{},
			},
			require.NoError,
			true, false,
			false,
		},
		{
			"one packet via close",
			args{
				-1,
				[]*networking.UDPPacket{{Time: now, Data: packet1}},
				[]*networking.UDPPacket{{Time: now, Data: packet1}},
			},
			require.NoError,
			false, true,
			false,
		},
		{
			"one packet via cancel",
			args{
				-1,
				[]*networking.UDPPacket{{Time: now, Data: packet1}},
				[]*networking.UDPPacket{{Time: now, Data: packet1}},
			},
			require.NoError,
			true, false,
			false,
		},
		{
			"two packets via close",
			args{
				-1,
				[]*networking.UDPPacket{
					{Time: now, Data: packet1},
					{Time: now.Add(100 * time.Millisecond), Data: packet2},
				},
				[]*networking.UDPPacket{
					{Time: now, Data: packet1},
					{Time: now.Add(100 * time.Millisecond), Data: packet2},
				},
			},
			require.NoError,
			false, true,
			true,
		},
		{
			"two packets via cancel",
			args{
				-1,
				[]*networking.UDPPacket{
					{Time: now, Data: packet1},
					{Time: now.Add(100 * time.Millisecond), Data: packet2},
				},
				[]*networking.UDPPacket{
					{Time: now, Data: packet1},
					{Time: now.Add(100 * time.Millisecond), Data: packet2},
				},
			},
			require.NoError,
			true, false,
			true,
		},
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

			// make sockets on a couple random high ports
			// add retries so we don't get false fails if the ports are in use
			e := &GoEnvironment{}

			randUDP := func() (*net.UDPAddr, networking.UDPConn) {
				for {
					addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 1024 + rand.Intn(65536-1024)}
					udp, err := e.ListenUDP("udp", addr)
					if oe, ok := err.(*net.OpError); ok && oe != nil {
						if se, ok := oe.Err.(*os.SyscallError); ok && se != nil {
							if se.Err == syscall.EADDRINUSE {
								// retry
								continue
							}
						}
					}
					require.NoError(t, err)
					return addr, udp
				}
			}

			// make a pair of sockets for sending and receiving
			recvAddr, udpRecv := randUDP()
			// TODO: shouldn't need a listen socket for this one, but that's all we have in the abstraction
			sendAddr, udpSend := randUDP()

			// make sure we close the sender eventually
			defer udpSend.Close()

			sendDone := make(chan struct{})
			recvDone := make(chan struct{})

			ctx, cancel := context.WithCancel(context.Background())
			receiveChan := make(chan *networking.UDPPacket, len(tt.args.send)+len(tt.args.wantReceive))

			// have to run the test code async to be concurrent with the sending
			var gotErr error
			go func() {
				defer close(recvDone)
				gotErr = udpRecv.ReadPackets(ctx, tt.args.maxSize, receiveChan)
			}()
			// start the sender
			sendStarted := time.Now()
			go func() {
				defer close(sendDone)
				// FIXME: share this with mock UDPConn.WithPacketSequence
				// this one is much simpler due to not watching a Context
				for i := range tt.args.send {
					packetOffset := tt.args.send[i].Time.Sub(now)
					packetDeadline := sendStarted.Add(packetOffset)
					timer := time.NewTimer(packetDeadline.Sub(time.Now()))
					<-timer.C
					udpSend.WriteToUDP(tt.args.send[i].Data, recvAddr)
				}
			}()

			// wait for completion
			<-sendDone
			// Need to wait long enough for the packet to e received before closing/cancelling
			// TODO: delay here is brittle, and makes all tests slow-ish
			<-time.NewTimer(5 * time.Millisecond).C
			if tt.closeSocket {
				require.NoError(t, udpRecv.Close())
			} else {
				// well, we need to close it _eventually_!
				defer udpRecv.Close()
			}
			if tt.cancelCtx {
				cancel()
			} else {
				// do cancel it eventually to release resources
				defer cancel()
			}
			<-recvDone

			tt.assertion(t, gotErr)

			gotReceive := make([]*networking.UDPPacket, 0, len(tt.args.wantReceive))
			for p := range receiveChan {
				gotReceive = append(gotReceive, p)
			}
			assert.Len(t, gotReceive, len(tt.args.wantReceive))
			// have to do custom testing because of timestamps
			for i := 0; i < len(gotReceive) && i < len(tt.args.wantReceive); i++ {
				want := tt.args.wantReceive[i]
				got := gotReceive[i]
				if want.Addr != nil {
					want.Addr.IP = util.NormalizeIP(want.Addr.IP)
					assert.Equal(t, want.Addr, got.Addr, "packet %d source addr", i)
				} else {
					assert.Equal(t, sendAddr, got.Addr, "packet %d source addr", i)
				}
				assert.Equal(t, want.Data, got.Data)

				// see notes elsewhere about timestamp comparison issues
				gotOffset := got.Time.Sub(sendStarted)
				wantOffset := want.Time.Sub(now)
				assert.GreaterOrEqual(t, int64(gotOffset), int64(wantOffset), "packet %d earliest receive time", i)
				assert.LessOrEqual(t, int64(gotOffset), int64(wantOffset+2*time.Millisecond), "packet %d latest receive time", i)
			}
		})
	}
}
