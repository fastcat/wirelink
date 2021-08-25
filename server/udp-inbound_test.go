package server

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/networking"
	netmocks "github.com/fastcat/wirelink/internal/networking/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/signing"
	"github.com/fastcat/wirelink/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinkServer_readPackets(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)

	// need real crypto keys for this test
	localPrivateKey, localPublicKey := testutils.MustKeyPair(t)
	remotePrivateKey, remotePublicKey := testutils.MustKeyPair(t)
	randomKey := testutils.MustKey(t)

	remoteSigner := signing.New(&remotePrivateKey)
	properSource := &net.UDPAddr{
		IP:   autopeer.AutoAddress(remotePublicKey),
		Port: rand.Intn(65535),
	}

	wrapAndSign := func(facts ...*fact.Fact) []byte {
		buffer := make([]byte, 0)
		for _, f := range facts {
			buffer = append(buffer, util.MustBytes(f.MarshalBinaryNow(now))...)
		}
		nonce, tag, err := remoteSigner.SignFor(buffer, &localPublicKey)
		require.NoError(t, err)
		sgf := &fact.Fact{
			Attribute: fact.AttributeSignedGroup,
			Subject:   &fact.PeerSubject{Key: remotePublicKey},
			Value:     &fact.SignedGroupValue{Nonce: nonce, Tag: tag, InnerBytes: buffer},
			Expires:   expires,
		}
		return util.MustBytes(sgf.MarshalBinary())
	}

	type fields struct {
		conn func(*testing.T) *netmocks.UDPConn
	}
	tests := []struct {
		name         string
		fields       fields
		assertion    require.ErrorAssertionFunc
		packets      []*networking.UDPPacket
		wantReceived []*ReceivedFact
		// TODO: add `long` flag for skipping tests with non-immediate timings
	}{
		{
			"empty",
			fields{},
			require.NoError,
			[]*networking.UDPPacket{},
			[]*ReceivedFact{},
		},
		{
			"one alive",
			fields{},
			require.NoError,
			[]*networking.UDPPacket{
				{
					Time: now,
					Addr: properSource,
					Data: wrapAndSign(facts.AliveFact(&remotePublicKey, expires)),
				},
			},
			[]*ReceivedFact{
				{
					fact:   facts.AliveFact(&remotePublicKey, expires),
					source: *properSource,
				},
			},
		},
		{
			"ignore unsigned",
			fields{},
			require.NoError,
			[]*networking.UDPPacket{
				{
					Time: now,
					Addr: properSource,
					Data: util.MustBytes(facts.AliveFact(&randomKey, expires).MarshalBinaryNow(now)),
				},
				{
					Time: now,
					Addr: properSource,
					Data: wrapAndSign(facts.AliveFact(&remotePublicKey, expires)),
				},
			},
			[]*ReceivedFact{
				{
					fact:   facts.AliveFact(&remotePublicKey, expires),
					source: *properSource,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var conn *netmocks.UDPConn
			if tt.fields.conn != nil {
				conn = tt.fields.conn(t)
			} else {
				conn = &netmocks.UDPConn{}
			}
			conn.WithPacketSequence(now, tt.packets...)
			conn.Test(t)
			s := &LinkServer{
				conn:   conn,
				eg:     &errgroup.Group{},
				ctx:    context.Background(),
				signer: signing.New(&localPrivateKey),
			}
			// deep channel to simplify extracting outputs
			received := make(chan *ReceivedFact, len(tt.wantReceived)+len(tt.packets))

			tt.assertion(t, s.readPackets(received))

			tt.assertion(t, s.eg.Wait())
			gotReceived := make([]*ReceivedFact, 0, len(tt.wantReceived))
			for r := range received {
				gotReceived = append(gotReceived, r)
			}
			// we have just enough `now` locking that we can safely use a plain equality comparison here
			assert.Equal(t, tt.wantReceived, gotReceived)
			conn.AssertExpectations(t)
		})
	}
}

func TestLinkServer_processSignedGroup(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)

	// this is doing crypto, so we need _real_ keys, not just random bytes
	localPrivKey, localPubKey := testutils.MustKeyPair(t)
	remotePrivKey, remotePubKey := testutils.MustKeyPair(t)
	localSigner := signing.New(&localPrivKey)
	remoteSigner := signing.New(&remotePrivKey)
	properSource := &net.UDPAddr{
		IP:   autopeer.AutoAddress(remotePubKey),
		Port: rand.Intn(65535),
	}
	improperSource := testutils.RandUDP4Addr(t)

	sign := func(f *fact.SignedGroupValue) *fact.SignedGroupValue {
		nonce, tag, err := remoteSigner.SignFor(f.InnerBytes, &localPubKey)
		require.NoError(t, err)
		f.Nonce = nonce
		f.Tag = tag
		return f
	}

	sgvFromBytes := func(data []byte) *fact.SignedGroupValue {
		return sign(&fact.SignedGroupValue{
			InnerBytes: data,
		})
	}
	svgFromFacts := func(facts ...*fact.Fact) *fact.SignedGroupValue {
		data := make([]byte, 0)
		for _, f := range facts {
			data = append(data, util.MustBytes(f.MarshalBinaryNow(now))...)
		}
		return sgvFromBytes(data)
	}
	rf := func(f *fact.Fact) *ReceivedFact {
		return &ReceivedFact{
			fact:   f,
			source: *properSource,
		}
	}
	corrupt := func(offset int, data []byte) /* []byte */ {
		inner := data[offset:]
		// using xor to ensure we change at least one bit, i.e. no matter what random value we get,
		// we will change the target byte
		inner[rand.Intn(len(inner))] ^= byte(1 + rand.Intn(255))
		// return data
	}
	corruptSGV := func(f *fact.SignedGroupValue) *fact.SignedGroupValue {
		pos := rand.Intn(len(f.Nonce) + len(f.Tag) + len(f.InnerBytes))
		if pos < len(f.Nonce) {
			t.Logf("Corrupting nonce")
			corrupt(0, f.Nonce[:])
		} else if pos < len(f.Nonce)+len(f.Tag) {
			t.Logf("Corrupting Tag")
			corrupt(0, f.Tag[:])
		} else {
			t.Logf("Corrupting InnerBytes")
			corrupt(0, f.InnerBytes)
		}
		return f
	}
	shorten := func(f *fact.SignedGroupValue) *fact.SignedGroupValue {
		// make sure we both shorten it by at least one byte, and leave at least one byte behind
		end := rand.Intn(len(f.InnerBytes)-1) + 1
		t.Logf("Shortening InnerBytes from %d to %d", len(f.InnerBytes), end)
		f.InnerBytes = f.InnerBytes[:end]
		return f
	}

	type fields struct {
		signer *signing.Signer
	}
	type args struct {
		f      *fact.Fact
		source *net.UDPAddr
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		assertion   require.ErrorAssertionFunc
		wantPackets []*ReceivedFact
	}{
		{
			"valid empty",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     sgvFromBytes([]byte{}),
				},
				properSource,
			},
			require.NoError,
			[]*ReceivedFact{},
		},
		{
			"valid alive",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     svgFromFacts(facts.AliveFact(&remotePubKey, expires)),
				},
				properSource,
			},
			require.NoError,
			[]*ReceivedFact{
				rf(facts.AliveFact(&remotePubKey, expires)),
			},
		},
		{
			"valid various",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value: svgFromFacts(
						facts.AliveFact(&remotePubKey, expires),
						facts.EndpointFactFull(properSource, &remotePubKey, expires),
					),
				},
				properSource,
			},
			require.NoError,
			[]*ReceivedFact{
				rf(facts.AliveFact(&remotePubKey, expires)),
				rf(facts.EndpointFactFull(properSource, &remotePubKey, expires)),
			},
		},
		{
			"corrupt",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     corruptSGV(svgFromFacts(facts.AliveFact(&remotePubKey, expires))),
				},
				properSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
		{
			"wrong source",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     svgFromFacts(facts.AliveFact(&remotePubKey, expires)),
				},
				improperSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
		{
			"truncated after signing",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     shorten(svgFromFacts(facts.AliveFact(&remotePubKey, expires))),
				},
				properSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
		{
			"truncated before signing",
			fields{
				signer: localSigner,
			},
			args{
				&fact.Fact{
					Attribute: fact.AttributeSignedGroup,
					Subject:   &fact.PeerSubject{Key: remotePubKey},
					Value:     sign(shorten(svgFromFacts(facts.AliveFact(&remotePubKey, expires)))),
				},
				properSource,
			},
			// TODO: require a specific error
			require.Error,
			[]*ReceivedFact{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				config:     &config.Server{},
				signer:     tt.fields.signer,
				peerConfig: newPeerConfigSet(),
			}
			// we make a channel with a huge buffer so that we can do this linearly
			// and not have goroutines and waits
			packetsChan := make(chan *ReceivedFact, 100)
			tt.assertion(t, s.processSignedGroup(tt.args.f, tt.args.source, now, packetsChan))
			close(packetsChan)
			packets := make([]*ReceivedFact, 0, 100)
			for p := range packetsChan {
				packets = append(packets, p)
			}
			assert.Equal(t, tt.wantPackets, packets)
		})
	}
}

func TestLinkServer_chunkReceived(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)

	var randRfs []*ReceivedFact
	rf := func(index int) *ReceivedFact {
		for len(randRfs) <= index {
			k := testutils.MustKey(t)
			randRfs = append(randRfs, &ReceivedFact{
				facts.AliveFact(&k, expires),
				*testutils.RandUDP4Addr(t),
			})
		}
		return randRfs[index]
	}
	rfs := func(indexes ...int) []*ReceivedFact {
		ret := make([]*ReceivedFact, len(indexes))
		for i, index := range indexes {
			ret[i] = rf(index)
		}
		return ret
	}

	type args struct {
		maxChunk    int
		chunkPeriod time.Duration
	}
	tests := []struct {
		name             string
		args             args
		assertion        require.ErrorAssertionFunc
		packets          []*ReceivedFact
		wantChunks       [][]*ReceivedFact
		wantBootIDChange bool
		// testing timing is a different test setup
	}{
		{
			"no data",
			args{
				maxChunk:    1,
				chunkPeriod: time.Second,
			},
			require.NoError,
			nil,
			[][]*ReceivedFact{},
			false,
		},
		{
			"chunk size",
			args{
				maxChunk:    5,
				chunkPeriod: time.Second,
			},
			require.NoError,
			rfs(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
			[][]*ReceivedFact{
				rfs(0, 1, 2, 3, 4),
				rfs(5, 6, 7, 8, 9),
				rfs(10, 11),
			},
			false,
		},
		{
			// can't test the issue of time going backwards here
			"change bootID on time jump",
			args{
				maxChunk: 1,
				// basically _any_ passage of time will be > 2x this
				chunkPeriod: time.Nanosecond,
			},
			require.NoError,
			rfs(0, 1),
			[][]*ReceivedFact{
				rfs(0),
				rfs(1),
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origBootID := uuid.Must(uuid.NewRandom())
			s := &LinkServer{
				ChunkPeriod: tt.args.chunkPeriod,
				bootID:      origBootID,
				stateAccess: &sync.Mutex{},
			}
			// make deep channels to avoid buffering problems
			packets := make(chan *ReceivedFact, len(tt.packets))
			// need +1 because there is an extra empty chunk sent at start
			// add *2+10 to avoid deadlocking on bugs/errors
			newFacts := make(chan []*ReceivedFact, len(tt.packets)*2+10)
			for _, p := range tt.packets {
				packets <- p
			}
			close(packets)
			tt.assertion(t, s.chunkReceived(packets, newFacts, tt.args.maxChunk))
			gotChunks := [][]*ReceivedFact{}
			first := true
			for chunk := range newFacts {
				// there's always a nil startup chunk, don't require tests to specify that
				// also ignore nil chunks in crazy-timing-bootID-changes mode
				if chunk == nil && (first || tt.wantBootIDChange) {
					first = false
					continue
				}
				gotChunks = append(gotChunks, chunk)
				first = false
			}
			assert.Equal(t, tt.wantChunks, gotChunks)
			if tt.wantBootIDChange {
				assert.NotEqual(t, origBootID, s.bootID)
			} else {
				assert.Equal(t, origBootID, s.bootID)
			}
		})
	}
}

func TestLinkServer_chunkReceived_slow(t *testing.T) {
	t.Logf("using CI scale: %d", testutils.CIScaleFactor)

	timeZero := time.Now()
	expires := timeZero.Add(DefaultFactTTL)

	var randRfs []*ReceivedFact
	rf := func(index int) *ReceivedFact {
		for len(randRfs) <= index {
			k := testutils.MustKey(t)
			randRfs = append(randRfs, &ReceivedFact{
				facts.AliveFact(&k, expires),
				*testutils.RandUDP4Addr(t),
			})
		}
		return randRfs[index]
	}
	rfs := func(indexes ...int) []*ReceivedFact {
		if len(indexes) == 0 {
			return nil
		}
		ret := make([]*ReceivedFact, len(indexes))
		for i, index := range indexes {
			ret[i] = rf(index)
		}
		return ret
	}

	type args struct {
		maxChunk    int
		chunkPeriod time.Duration
	}
	type send struct {
		offset time.Duration
		packet *ReceivedFact
	}
	type receive struct {
		offset time.Duration
		chunk  []*ReceivedFact
	}

	sendAtMs := func(ms, index int) send {
		return send{offset: time.Duration(ms) * time.Millisecond, packet: rf(index)}
	}
	receiveAtMs := func(ms int, indexes ...int) receive {
		return receive{offset: time.Duration(ms) * time.Millisecond, chunk: rfs(indexes...)}
	}

	tests := []struct {
		name       string
		args       args
		assertion  require.ErrorAssertionFunc
		packets    []send
		wantChunks []receive
		long       bool
	}{
		{
			"empty",
			args{1, time.Hour},
			require.NoError,
			nil,
			[]receive{},
			false,
		},
		{
			"two quick",
			args{3, time.Hour},
			require.NoError,
			[]send{
				sendAtMs(1, 0),
				sendAtMs(2, 1),
			},
			[]receive{
				receiveAtMs(2, 0, 1),
			},
			false,
		},
		{
			"two delayed",
			args{2, 100 * time.Millisecond},
			require.NoError,
			[]send{
				sendAtMs(50, 0),
				sendAtMs(150, 1),
			},
			[]receive{
				receiveAtMs(100, 0),
				receiveAtMs(150, 1),
			},
			true,
		},
		{
			"two chunks, pause after each",
			args{3, 100 * time.Millisecond},
			require.NoError,
			[]send{
				sendAtMs(50, 0),
				sendAtMs(55, 1),
				sendAtMs(250, 2),
				sendAtMs(255, 3),
				{offset: 350 * time.Millisecond},
			},
			[]receive{
				receiveAtMs(100, 0, 1),
				{offset: 200 * time.Millisecond},
				receiveAtMs(300, 2, 3),
			},
			true,
		},
		{
			"buffer fill with delay",
			args{3, 100 * time.Millisecond},
			require.NoError,
			[]send{
				sendAtMs(10, 0),
				sendAtMs(20, 1),
				sendAtMs(30, 2),
				sendAtMs(40, 3),
				sendAtMs(110, 4),
				sendAtMs(120, 5),
				{offset: 210 * time.Millisecond},
			},
			[]receive{
				receiveAtMs(30, 0, 1, 2),
				receiveAtMs(100, 3),
				receiveAtMs(200, 4, 5),
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// skip long tests
			if tt.long && testing.Short() {
				t.SkipNow()
			}

			s := &LinkServer{
				ChunkPeriod: tt.args.chunkPeriod,
			}
			// for this test, use the same limited buffer for the incoming packets as
			// the real server
			packets := make(chan *ReceivedFact, 1)
			// but still make a deep channel for the output to simplify test logic
			newFacts := make(chan []*ReceivedFact, len(tt.packets)+1)
			doneSend := make(chan struct{})
			doneReceive := make(chan struct{})
			start := time.Now()
			go func() {
				defer close(doneSend)
				defer close(packets)
				// this initial duration will be ignored
				timer := time.NewTimer(time.Hour)
				defer timer.Stop()
				for _, p := range tt.packets {
					currentOffset := time.Since(start)
					delay := p.offset - currentOffset
					if delay > 0 {
						timer.Reset(delay)
						<-timer.C
					}
					// sending a nil packet is valid, so we need to check flags if that's what we've got
					if p.packet != nil {
						// treat the packet expires as an offset from timeZero, update it to be that offset from now
						p.packet.fact.Expires.Add(time.Since(timeZero))
						packets <- p.packet
					} else {
						packets <- nil
					}
				}
			}()
			var gotChunks []receive
			go func() {
				defer close(doneReceive)
				for chunk := range newFacts {
					gotChunks = append(gotChunks, receive{time.Since(start), chunk})
				}
			}()
			tt.assertion(t, s.chunkReceived(packets, newFacts, tt.args.maxChunk))
			// wait for goroutines
			<-doneSend
			<-doneReceive
			// there's always a nil startup chunk, don't require tests to specify that
			wantChunks := append([]receive{{0, nil}}, tt.wantChunks...)
			assert.Len(t, gotChunks, len(wantChunks))
			for i := 0; i < len(gotChunks) && i < len(wantChunks); i++ {
				assert.Equal(t, wantChunks[i].chunk, gotChunks[i].chunk, "Received chunk %d", i)
				// need to allow some slop in the receive timing
				// using `assert.InDelta` would be nice, but we really need an asymmetric behavior
				// it's OK if things are a little late due to timing issues,
				// but if they are early, there is definitely a bug
				// have to cast to int64 because of https://github.com/stretchr/testify/issues/780
				assert.GreaterOrEqual(t, int64(gotChunks[i].offset), int64(wantChunks[i].offset),
					"Received timing %d: must not be early", i)
				assert.LessOrEqual(t, int64(gotChunks[i].offset), int64(wantChunks[i].offset+10*time.Millisecond*testutils.CIScaleFactorDuration),
					"Received timing %d: must not be late", i)
			}
		})
	}
}

func Test_pruneRemovedLocalFacts(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)

	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	type args struct {
		chunk     []*fact.Fact
		lastLocal []*fact.Fact
		newLocal  []*fact.Fact
	}
	tests := []struct {
		name string
		args args
		want []*fact.Fact
	}{
		{
			"empty",
			args{},
			[]*fact.Fact{},
		},
		{
			"remote only",
			args{
				chunk: []*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
			},
			[]*fact.Fact{
				facts.AliveFact(&k1, expires),
			},
		},
		{
			"retained local in chunk",
			args{
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
			},
			[]*fact.Fact{
				facts.AliveFact(&k1, expires),
			},
		},
		{
			"retained local not in chunk",
			args{
				[]*fact.Fact{
					facts.AliveFact(&k2, expires),
				},
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
			},
			[]*fact.Fact{
				facts.AliveFact(&k2, expires),
			},
		},
		{
			"removed local in chunk",
			args{
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
				[]*fact.Fact{},
			},
			[]*fact.Fact{},
		},
		{
			"removed local not in chunk",
			args{
				[]*fact.Fact{
					facts.AliveFact(&k1, expires),
				},
				[]*fact.Fact{
					facts.AliveFact(&k2, expires),
				},
				[]*fact.Fact{},
			},
			[]*fact.Fact{
				facts.AliveFact(&k1, expires),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pruneRemovedLocalFacts(tt.args.chunk, tt.args.lastLocal, tt.args.newLocal))
		})
	}
}

func TestLinkServer_processOneChunk(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)

	wgIface := fmt.Sprintf("wg%d", rand.Int())

	remoteKey := testutils.MustKey(t)

	properSource := &net.UDPAddr{
		IP:   autopeer.AutoAddress(remoteKey),
		Port: rand.Intn(65535),
	}
	alternateEndpoint := testutils.RandUDP4Addr(t)

	rf := func(f *fact.Fact) *ReceivedFact {
		return &ReceivedFact{
			fact:   f,
			source: *properSource,
		}
	}

	mockDevice := func(dev *wgtypes.Device) func(*testing.T) *mocks.WgClient {
		if dev == nil {
			dev = &wgtypes.Device{}
		}
		if dev.Name == "" {
			dev.Name = wgIface
		}
		return func(t *testing.T) *mocks.WgClient {
			ret := &mocks.WgClient{}
			ret.On("Device", wgIface).Return(dev, nil)
			return ret
		}
	}

	type fields struct {
		config        *config.Server
		net           *netmocks.Environment
		ctrl          func(*testing.T) *mocks.WgClient
		peerKnowledge *peerKnowledgeSet
	}
	type args struct {
		currentFacts   []*fact.Fact
		lastLocalFacts []*fact.Fact
		chunk          []*ReceivedFact
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		wantUniqueFacts   []*fact.Fact
		wantNewLocalFacts []*fact.Fact
		assertion         require.ErrorAssertionFunc
	}{
		{
			"empty 1",
			fields{
				&config.Server{Iface: wgIface},
				&netmocks.Environment{},
				mockDevice(nil),
				nil,
			},
			args{},
			[]*fact.Fact{},
			nil,
			require.NoError,
		},
		{
			"empty 2",
			fields{
				&config.Server{Iface: wgIface},
				&netmocks.Environment{},
				mockDevice(nil),
				nil,
			},
			args{
				[]*fact.Fact{},
				[]*fact.Fact{},
				[]*ReceivedFact{},
			},
			[]*fact.Fact{},
			// this won't come back as non-nil unless something had to get append()ed to it
			nil,
			require.NoError,
		},
		{
			"received one new endpoint fact",
			fields{
				&config.Server{Iface: wgIface},
				&netmocks.Environment{},
				mockDevice(&wgtypes.Device{
					Peers: []wgtypes.Peer{
						{
							PublicKey:  remoteKey,
							AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(remoteKey)},
						},
					},
				}),
				nil,
			},
			args{
				chunk: []*ReceivedFact{
					rf(facts.EndpointFactFull(alternateEndpoint, &remoteKey, expires)),
				},
			},
			[]*fact.Fact{
				facts.EndpointFactFull(alternateEndpoint, &remoteKey, expires),
			},
			nil,
			require.NoError,
		},
		{
			"merge new remote with new local endpoint",
			fields{
				&config.Server{Iface: wgIface},
				&netmocks.Environment{},
				mockDevice(&wgtypes.Device{
					Peers: []wgtypes.Peer{
						{
							PublicKey:         remoteKey,
							AllowedIPs:        []net.IPNet{autopeer.AutoAddressNet(remoteKey)},
							Endpoint:          alternateEndpoint,
							LastHandshakeTime: now,
						},
					},
				}),
				nil,
			},
			args{
				chunk: []*ReceivedFact{
					rf(facts.EndpointFactFull(alternateEndpoint, &remoteKey, expires)),
				},
			},
			[]*fact.Fact{
				facts.EndpointFactFull(alternateEndpoint, &remoteKey, expires),
			},
			[]*fact.Fact{
				facts.EndpointFactFull(alternateEndpoint, &remoteKey, expires),
			},
			require.NoError,
		},
		{
			// TODO: the current result of this test is arguably a bug, but it's a very
			// weird situation to have happen, and will be auto-recovered gracefully,
			// and so is not of great concern
			"removed local fact also received",
			fields{
				&config.Server{Iface: wgIface},
				&netmocks.Environment{},
				mockDevice(&wgtypes.Device{
					Peers: []wgtypes.Peer{
						{
							PublicKey:  remoteKey,
							AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(remoteKey)},
						},
					},
				}),
				nil,
			},
			args{
				currentFacts: []*fact.Fact{
					facts.EndpointFactFull(alternateEndpoint, &remoteKey, expires),
				},
				lastLocalFacts: []*fact.Fact{
					facts.EndpointFactFull(alternateEndpoint, &remoteKey, expires),
				},
				chunk: []*ReceivedFact{},
			},
			[]*fact.Fact{},
			nil,
			require.NoError,
		},
		{
			"prune expired and untrusted",
			fields{
				&config.Server{Iface: wgIface},
				&netmocks.Environment{},
				mockDevice(&wgtypes.Device{
					Peers: []wgtypes.Peer{
						{
							PublicKey:  remoteKey,
							AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(remoteKey)},
						},
					},
				}),
				nil,
			},
			args{
				currentFacts: []*fact.Fact{
					// this fact is expired, it will be removed
					facts.EndpointFactFull(alternateEndpoint, &remoteKey, now.Add(-time.Second)),
				},
				lastLocalFacts: []*fact.Fact{},
				chunk: []*ReceivedFact{
					// this fact is expired, it will be removed
					rf(facts.EndpointFactFull(properSource, &remoteKey, now.Add(-time.Millisecond))),
					// this fact is untrusted, it will be removed
					rf(facts.AllowedIPFactFull(testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 32), &remoteKey, expires)),
				},
			},
			[]*fact.Fact{},
			nil,
			require.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := tt.fields.ctrl(t)
			ctrl.Test(t)
			tt.fields.net.Test(t)
			tt.fields.net.WithKnownInterfaces()
			if tt.fields.peerKnowledge == nil {
				tt.fields.peerKnowledge = newPKS()
			}
			s := &LinkServer{
				stateAccess:   &sync.Mutex{},
				config:        tt.fields.config,
				net:           tt.fields.net,
				ctrl:          ctrl,
				peerKnowledge: tt.fields.peerKnowledge,
				FactTTL:       DefaultFactTTL,
				ChunkPeriod:   DefaultChunkPeriod,
			}
			gotUniqueFacts, gotNewLocalFacts, err := s.processOneChunk(tt.args.currentFacts, tt.args.lastLocalFacts, tt.args.chunk, now)
			tt.assertion(t, err)
			ctrl.AssertExpectations(t)
			tt.fields.net.AssertExpectations(t)
			assert.Equal(t, tt.wantUniqueFacts, gotUniqueFacts)
			assert.Equal(t, tt.wantNewLocalFacts, gotNewLocalFacts)
		})
	}
}
