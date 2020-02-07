package server

import (
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
	netmocks "github.com/fastcat/wirelink/internal/networking/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/signing"
	"github.com/fastcat/wirelink/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinkServer_processSignedGroup(t *testing.T) {
	now := time.Now()
	expires := now.Add(FactTTL)

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

	sgvFromBytes := func(t *testing.T, data []byte) *fact.SignedGroupValue {
		return sign(&fact.SignedGroupValue{
			InnerBytes: data,
		})
	}
	svgFromFacts := func(t *testing.T, facts ...*fact.Fact) *fact.SignedGroupValue {
		data := make([]byte, 0)
		for _, f := range facts {
			data = append(data, util.MustBytes(f.MarshalBinaryNow(now))...)
		}
		return sgvFromBytes(t, data)
	}
	rf := func(f *fact.Fact) *ReceivedFact {
		return &ReceivedFact{
			fact:   f,
			source: *properSource,
		}
	}
	corrupt := func(offset int, data []byte) []byte {
		inner := data[offset:]
		// using xor to ensure we change at least one bit, i.e. no matter what random value we get,
		// we will change the target byte
		inner[rand.Intn(len(inner))] ^= byte(1 + rand.Intn(255))
		return data
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
					Value:     sgvFromBytes(t, []byte{}),
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
					Value:     svgFromFacts(t, facts.AliveFact(&remotePubKey, expires)),
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
					Value: svgFromFacts(t,
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
					Value:     corruptSGV(svgFromFacts(t, facts.AliveFact(&remotePubKey, expires))),
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
					Value:     svgFromFacts(t, facts.AliveFact(&remotePubKey, expires)),
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
					Value:     shorten(svgFromFacts(t, facts.AliveFact(&remotePubKey, expires))),
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
					Value:     sign(shorten(svgFromFacts(t, facts.AliveFact(&remotePubKey, expires)))),
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
				config: &config.Server{},
				signer: tt.fields.signer,
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

func Test_pruneRemovedLocalFacts(t *testing.T) {
	now := time.Now()
	expires := now.Add(FactTTL)

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
	expires := now.Add(FactTTL)

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
						wgtypes.Peer{
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
						wgtypes.Peer{
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
						wgtypes.Peer{
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
						wgtypes.Peer{
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
