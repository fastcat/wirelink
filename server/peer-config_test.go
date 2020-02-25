package server

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/testutils"
	factutils "github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/signing"
	"github.com/fastcat/wirelink/trust"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkServer_configurePeers(t *testing.T) {
	type fields struct {
		bootID        uuid.UUID
		stateAccess   *sync.Mutex
		config        *config.Server
		net           networking.Environment
		conn          networking.UDPConn
		addr          net.UDPAddr
		ctrl          internal.WgClient
		eg            *errgroup.Group
		ctx           context.Context
		cancel        context.CancelFunc
		peerKnowledge *peerKnowledgeSet
		peerConfig    *peerConfigSet
		signer        *signing.Signer
	}
	type args struct {
		factsRefreshed <-chan []*fact.Fact
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				bootID:        tt.fields.bootID,
				stateAccess:   tt.fields.stateAccess,
				config:        tt.fields.config,
				net:           tt.fields.net,
				conn:          tt.fields.conn,
				addr:          tt.fields.addr,
				ctrl:          tt.fields.ctrl,
				eg:            tt.fields.eg,
				ctx:           tt.fields.ctx,
				cancel:        tt.fields.cancel,
				peerKnowledge: tt.fields.peerKnowledge,
				peerConfig:    tt.fields.peerConfig,
				signer:        tt.fields.signer,
			}
			err := s.configurePeers(tt.args.factsRefreshed)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}

			// TODO: check mocks
		})
	}
}

func TestLinkServer_configurePeersOnce(t *testing.T) {
	now := time.Now()
	unhealthyAgo := now.Add(-time.Hour / 2)
	startTime := now.Add(-time.Hour)
	expiresFuture := now.Add(DefaultFactTTL)

	wgIface := fmt.Sprintf("wg%d", rand.Int())

	// there's no actual differences between these keys, names are just to make
	// test intent easy to read
	localKey := testutils.MustKey(t)
	remoteController1Key := testutils.MustKey(t)
	remoteController2Key := testutils.MustKey(t)
	remoteLeaf1Key := testutils.MustKey(t)

	leaf1Endpoint := testutils.RandUDP4Addr(t)
	leaf1AIP32 := testutils.RandIPNet(t, net.IPv4len, nil, nil, 32)
	leaf1AIP32wrong := testutils.RandIPNet(t, net.IPv4len, nil, nil, 32)

	// t.Logf("Local is %s", localKey)
	// t.Logf("Remote trusted 1 is %s", remoteController1Key)
	// t.Logf("Remote trusted 2 is %s", remoteController2Key)
	// t.Logf("Remote leaf 1 is %s", remoteLeaf1Key)

	type fields struct {
		config        *config.Server
		ctrl          func(*testing.T) *mocks.WgClient
		peerKnowledge *peerKnowledgeSet
		peerStates    map[wgtypes.Key]*apply.PeerConfigState
	}
	type args struct {
		newFacts  []*fact.Fact
		dev       *wgtypes.Device
		startTime time.Time
		now       time.Time
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			"no-op",
			fields{},
			args{
				dev:       &wgtypes.Device{},
				startTime: now,
				now:       now,
			},
		},
		{
			"add new peer without details",
			fields{
				buildConfig(wgIface).withPeer(remoteController1Key, &config.Peer{
					Trust: trust.Ptr(trust.Membership),
				}).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey:  remoteLeaf1Key,
								AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(remoteLeaf1Key)},
								// this shouldn't matter since we're adding it, but we need to match, so it needs to be here
								ReplaceAllowedIPs: true,
							},
						},
					}).Return(nil)
					return ret
				},
				newPKS(),
				map[wgtypes.Key]*apply.PeerConfigState{},
			},
			args{
				[]*fact.Fact{
					factutils.MemberFactFull(&remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
				},
				startTime,
				now,
			},
		},
		{
			// should still only add the basic peer since we don't have a handshake yet,
			// no AIPs in the initial setup, but do add an endpoint
			"add new peer with details",
			fields{
				buildConfig(wgIface).withPeer(remoteController1Key, &config.Peer{
					Trust: trust.Ptr(trust.Membership),
				}).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey:  remoteLeaf1Key,
								Endpoint:   leaf1Endpoint,
								AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(remoteLeaf1Key)},
								// this shouldn't matter since we're adding it, but we need to match, so it needs to be here
								ReplaceAllowedIPs: true,
							},
						},
					}).Return(nil)
					return ret
				},
				newPKS(),
				map[wgtypes.Key]*apply.PeerConfigState{},
			},
			args{
				[]*fact.Fact{
					factutils.MemberFactFull(&remoteLeaf1Key, expiresFuture),
					factutils.AllowedIPFactFull(leaf1AIP32, &remoteLeaf1Key, expiresFuture),
					factutils.EndpointFactFull(leaf1Endpoint, &remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
				},
				startTime,
				now,
			},
		},
		{
			"delete peer with details",
			fields{
				buildConfig(wgIface).withPeer(remoteController1Key, &config.Peer{
					Trust: trust.Ptr(trust.Membership),
				}).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey: remoteLeaf1Key,
								Remove:    true,
							},
						},
					}).Return(nil)
					return ret
				},
				newPKS(),
				map[wgtypes.Key]*apply.PeerConfigState{
					remoteController1Key: makePCS(t, true, true, true),
				},
			},
			args{
				[]*fact.Fact{
					factutils.AllowedIPFactFull(leaf1AIP32, &remoteLeaf1Key, expiresFuture),
					factutils.EndpointFactFull(leaf1Endpoint, &remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey: remoteLeaf1Key,
						},
					},
				},
				startTime,
				now,
			},
		},
		{
			"keep peer 50% controllers online",
			fields{
				buildConfig(wgIface).withPeer(remoteController1Key, &config.Peer{
					Trust: trust.Ptr(trust.Membership),
				}).withPeer(remoteController2Key, &config.Peer{
					Trust: trust.Ptr(trust.Membership),
				}).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					// no calls expected
					return ret
				},
				newPKS(),
				map[wgtypes.Key]*apply.PeerConfigState{
					remoteController1Key: makePCS(t, true, true, true),
					remoteController2Key: makePCS(t, false, false, false),
				},
			},
			args{
				[]*fact.Fact{
					factutils.MemberFactFull(&remoteLeaf1Key, expiresFuture),
					factutils.AllowedIPFactFull(leaf1AIP32, &remoteLeaf1Key, expiresFuture),
					factutils.EndpointFactFull(leaf1Endpoint, &remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey:  remoteLeaf1Key,
							AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(remoteLeaf1Key)},
							Endpoint:   leaf1Endpoint,
						},
					},
				},
				startTime,
				now,
			},
		},
		{
			"add aip to healthy-alive peer",
			fields{
				// don't need config for this one, just trusted facts
				buildConfig(wgIface).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey:  remoteLeaf1Key,
								AllowedIPs: []net.IPNet{leaf1AIP32},
								UpdateOnly: true,
							},
						},
					}).Return(nil)
					return ret
				},
				newPKS().mockPeerAlive(remoteLeaf1Key, expiresFuture, nil),
				map[wgtypes.Key]*apply.PeerConfigState{
					// nothing here because this routine _updates_ PCS, not uses it
				},
			},
			args{
				[]*fact.Fact{
					factutils.MemberFactFull(&remoteLeaf1Key, expiresFuture),
					factutils.AllowedIPFactFull(leaf1AIP32, &remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey:         remoteLeaf1Key,
							AllowedIPs:        []net.IPNet{autopeer.AutoAddressNet(remoteLeaf1Key)},
							Endpoint:          leaf1Endpoint,
							LastHandshakeTime: now,
						},
					},
				},
				startTime,
				now,
			},
		},
		{
			"replace aip on healthy-alive peer with wrong value",
			fields{
				// don't need config for this one, just trusted facts
				buildConfig(wgIface).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey: remoteLeaf1Key,
								// have to sort this slice to make things match consistently
								AllowedIPs: util.SortIPNetSlice([]net.IPNet{
									autopeer.AutoAddressNet(remoteLeaf1Key),
									leaf1AIP32,
								}),
								ReplaceAllowedIPs: true,
								UpdateOnly:        true,
							},
						},
					}).Return(nil)
					return ret
				},
				newPKS().mockPeerAlive(remoteLeaf1Key, expiresFuture, nil),
				map[wgtypes.Key]*apply.PeerConfigState{
					// nothing here because this routine _updates_ PCS, not uses it
				},
			},
			args{
				[]*fact.Fact{
					factutils.MemberFactFull(&remoteLeaf1Key, expiresFuture),
					factutils.AllowedIPFactFull(leaf1AIP32, &remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey: remoteLeaf1Key,
							AllowedIPs: []net.IPNet{
								autopeer.AutoAddressNet(remoteLeaf1Key),
								leaf1AIP32wrong,
							},
							Endpoint:          leaf1Endpoint,
							LastHandshakeTime: now,
						},
					},
				},
				startTime,
				now,
			},
		},
		{
			"keep aip on healthy-notalive peer",
			fields{
				// don't need config for this one, just trusted facts
				buildConfig(wgIface).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					// should not reconfigure in this case
					return ret
				},
				newPKS(),
				map[wgtypes.Key]*apply.PeerConfigState{},
			},
			args{
				[]*fact.Fact{
					factutils.MemberFactFull(&remoteLeaf1Key, expiresFuture),
					factutils.AllowedIPFactFull(leaf1AIP32, &remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey: remoteLeaf1Key,
							AllowedIPs: []net.IPNet{
								autopeer.AutoAddressNet(remoteLeaf1Key),
								leaf1AIP32,
							},
							Endpoint:          leaf1Endpoint,
							LastHandshakeTime: now,
						},
					},
				},
				startTime,
				now,
			},
		},
		{
			"remove aip from unhealthy-notalive peer",
			fields{
				// don't need config for this one, just trusted facts
				buildConfig(wgIface).Build(),
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					// expect to reconfigire peer with just auto-ip
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey:         remoteLeaf1Key,
								AllowedIPs:        []net.IPNet{autopeer.AutoAddressNet(remoteLeaf1Key)},
								ReplaceAllowedIPs: true,
								UpdateOnly:        true,
							},
						},
					}).Return(nil)
					return ret
				},
				newPKS(),
				map[wgtypes.Key]*apply.PeerConfigState{},
			},
			args{
				[]*fact.Fact{
					factutils.MemberFactFull(&remoteLeaf1Key, expiresFuture),
					factutils.AllowedIPFactFull(leaf1AIP32, &remoteLeaf1Key, expiresFuture),
				},
				&wgtypes.Device{
					Name:      wgIface,
					PublicKey: localKey,
					Peers: []wgtypes.Peer{
						{
							PublicKey: remoteLeaf1Key,
							AllowedIPs: []net.IPNet{
								autopeer.AutoAddressNet(remoteLeaf1Key),
								leaf1AIP32,
							},
							Endpoint:          leaf1Endpoint,
							LastHandshakeTime: unhealthyAgo,
						},
					},
				},
				startTime,
				now,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctrl *mocks.WgClient
			if tt.fields.ctrl != nil {
				ctrl = tt.fields.ctrl(t)
				ctrl.Test(t)
			}
			if tt.fields.peerKnowledge != nil && tt.fields.peerKnowledge.access == nil {
				tt.fields.peerKnowledge.access = &sync.RWMutex{}
			}
			if tt.fields.config == nil {
				tt.fields.config = buildConfig(wgIface).Build()
			}
			s := &LinkServer{
				stateAccess:   &sync.Mutex{},
				config:        tt.fields.config,
				ctrl:          ctrl,
				peerKnowledge: tt.fields.peerKnowledge,
				peerConfig: &peerConfigSet{
					psm:        &sync.Mutex{},
					peerStates: tt.fields.peerStates,
				},
				signer: &signing.Signer{PublicKey: localKey},
			}
			s.configurePeersOnce(tt.args.newFacts, tt.args.dev, tt.args.startTime, tt.args.now)

			if ctrl != nil {
				ctrl.AssertExpectations(t)
			}

			// TODO: hooks to assert changes in peerKnowledge
			// TODO: hooks to assert changes in peerStates
		})
	}
}

func deviceWithPeerSimple(key wgtypes.Key) *wgtypes.Device {
	return &wgtypes.Device{
		Peers: []wgtypes.Peer{
			{
				PublicKey: key,
			},
		},
	}
}

func deviceWithPeers(peers ...wgtypes.Peer) *wgtypes.Device {
	return &wgtypes.Device{
		Peers: peers,
	}
}

func TestLinkServer_deletePeers(t *testing.T) {
	now := time.Now()
	wgIface := fmt.Sprintf("wg%d", rand.Int())
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)
	k3 := testutils.MustKey(t)
	ipnRouter1 := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	ipnRouter2 := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	ipnHost := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 32)

	type fields struct {
		config     *config.Server
		peerStates map[wgtypes.Key]*apply.PeerConfigState
		ctrl       func(*testing.T) *mocks.WgClient
	}
	type args struct {
		dev        *wgtypes.Device
		removePeer map[wgtypes.Key]bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			"no-op",
			fields{
				&config.Server{},
				nil,
				func(t *testing.T) *mocks.WgClient {
					return &mocks.WgClient{}
				},
			},
			args{&wgtypes.Device{}, nil},
			false,
		},
		{
			"delete one",
			fields{
				// need a peer that has Membership
				buildConfig(wgIface).withPeer(k1, &config.Peer{
					Trust: trust.Ptr(trust.Membership),
				}).Build(),
				map[wgtypes.Key]*apply.PeerConfigState{
					// k1 must be alive & healthy, for a while, for its Membership trust
					// to take effect
					k1: makePCS(t, true, true, true),
				},
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey: k2,
								Remove:    true,
							},
						},
					}).Return(nil)
					return ret
				},
			},
			args{
				// k2 must exist to delete it
				deviceWithPeerSimple(k2),
				map[wgtypes.Key]bool{
					k2: true,
				},
			},
			false,
		},
		{
			"don't delete remote routers in full-auto mode",
			fields{
				buildConfig(wgIface).Build(),
				map[wgtypes.Key]*apply.PeerConfigState{
					// need a live router to enable deletion in this mode
					k3: makePCS(t, true, true, true),
				},
				func(t *testing.T) *mocks.WgClient {
					// should only delete k1, not k2 or k3
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey: k1,
								Remove:    true,
							},
						},
					}).Return(nil)
					return ret
				},
			},
			args{
				// we include a non-router that we do expect to be deleted to ensure that
				// the router peer is not deleted for the right reasons, and a second
				// healthy router that is required to enable deletion
				deviceWithPeers(wgtypes.Peer{
					PublicKey:  k1,
					AllowedIPs: []net.IPNet{ipnHost},
				}, wgtypes.Peer{
					PublicKey:  k2,
					AllowedIPs: []net.IPNet{ipnRouter1},
				}, wgtypes.Peer{
					PublicKey:  k3,
					AllowedIPs: []net.IPNet{ipnRouter2},
				}),
				map[wgtypes.Key]bool{
					k1: true,
					k2: true,
				},
			},
			false,
		},
		{
			"do delete remote routers when there is another trust source",
			fields{
				// need a peer that has Membership
				buildConfig(wgIface).withPeer(k1, &config.Peer{
					Trust: trust.Ptr(trust.Membership),
				}).Build(),
				map[wgtypes.Key]*apply.PeerConfigState{
					// k1 must be alive & healthy, for a while, for its Membership trust
					// to take effect
					k1: makePCS(t, true, true, true),
				},
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("ConfigureDevice", wgIface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey: k2,
								Remove:    true,
							},
						},
					}).Return(nil)
					return ret
				},
			},
			args{
				// k2 must exist to delete it
				deviceWithPeers(wgtypes.Peer{
					PublicKey:  k2,
					AllowedIPs: []net.IPNet{ipnRouter1},
				}),
				map[wgtypes.Key]bool{
					k2: true,
				},
			},
			false,
		},
		// TODO: don't delete when local is router
		// TODO: don't delete when local is Membership
		// TODO: don't delete when remote is statically valid
		// TODO: don't delete when Membership is offline
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := tt.fields.ctrl(t)
			ctrl.Test(t)
			s := &LinkServer{
				stateAccess: &sync.Mutex{},
				config:      tt.fields.config,
				ctrl:        ctrl,
				peerConfig: &peerConfigSet{
					peerStates: tt.fields.peerStates,
					psm:        &sync.Mutex{},
				},
			}
			err := s.deletePeers(tt.args.dev, tt.args.removePeer, now)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}
			// shouldn't change `peerConfig`, other than it having a different mutex
			assert.Equal(t, tt.fields.peerStates, s.peerConfig.peerStates)
			ctrl.AssertExpectations(t)
		})
	}
}

func TestLinkServer_configurePeer(t *testing.T) {
	type fields struct {
		bootID        uuid.UUID
		stateAccess   *sync.Mutex
		config        *config.Server
		net           networking.Environment
		conn          networking.UDPConn
		addr          net.UDPAddr
		ctrl          internal.WgClient
		eg            *errgroup.Group
		ctx           context.Context
		cancel        context.CancelFunc
		peerKnowledge *peerKnowledgeSet
		peerConfig    *peerConfigSet
		signer        *signing.Signer
	}
	type args struct {
		inputState       *apply.PeerConfigState
		peer             *wgtypes.Peer
		facts            []*fact.Fact
		allowDeconfigure bool
		allowAdd         bool
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantState *apply.PeerConfigState
		wantErr   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				bootID:        tt.fields.bootID,
				stateAccess:   tt.fields.stateAccess,
				config:        tt.fields.config,
				net:           tt.fields.net,
				conn:          tt.fields.conn,
				addr:          tt.fields.addr,
				ctrl:          tt.fields.ctrl,
				eg:            tt.fields.eg,
				ctx:           tt.fields.ctx,
				cancel:        tt.fields.cancel,
				peerKnowledge: tt.fields.peerKnowledge,
				peerConfig:    tt.fields.peerConfig,
				signer:        tt.fields.signer,
			}
			gotState, err := s.configurePeer(tt.args.inputState, tt.args.peer, tt.args.facts, tt.args.allowDeconfigure, tt.args.allowAdd)
			if tt.wantErr {
				require.NotNil(t, err, "LinkServer.configurePeer() error")
			} else {
				require.Nil(t, err, "LinkServer.configurePeer() error")
			}
			assert.Equal(t, tt.wantState, gotState)

			// TODO: check mocks
		})
	}
}
