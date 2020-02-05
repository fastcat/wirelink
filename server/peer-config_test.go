package server

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/signing"
	"github.com/fastcat/wirelink/trust"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinkServer_configurePeers(t *testing.T) {
	type fields struct {
		bootID          uuid.UUID
		stateAccess     *sync.Mutex
		config          *config.Server
		net             networking.Environment
		conn            *net.UDPConn
		addr            net.UDPAddr
		ctrl            internal.WgClient
		eg              *errgroup.Group
		ctx             context.Context
		cancel          context.CancelFunc
		peerKnowledge   *peerKnowledgeSet
		peerConfig      *peerConfigSet
		signer          *signing.Signer
		printsRequested *int32
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
				bootID:          tt.fields.bootID,
				stateAccess:     tt.fields.stateAccess,
				config:          tt.fields.config,
				net:             tt.fields.net,
				conn:            tt.fields.conn,
				addr:            tt.fields.addr,
				ctrl:            tt.fields.ctrl,
				eg:              tt.fields.eg,
				ctx:             tt.fields.ctx,
				cancel:          tt.fields.cancel,
				peerKnowledge:   tt.fields.peerKnowledge,
				peerConfig:      tt.fields.peerConfig,
				signer:          tt.fields.signer,
				printsRequested: tt.fields.printsRequested,
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
	type fields struct {
		bootID          uuid.UUID
		stateAccess     *sync.Mutex
		config          *config.Server
		net             networking.Environment
		conn            *net.UDPConn
		addr            net.UDPAddr
		ctrl            internal.WgClient
		eg              *errgroup.Group
		ctx             context.Context
		cancel          context.CancelFunc
		peerKnowledge   *peerKnowledgeSet
		peerConfig      *peerConfigSet
		signer          *signing.Signer
		printsRequested *int32
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
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				bootID:          tt.fields.bootID,
				stateAccess:     tt.fields.stateAccess,
				config:          tt.fields.config,
				net:             tt.fields.net,
				conn:            tt.fields.conn,
				addr:            tt.fields.addr,
				ctrl:            tt.fields.ctrl,
				eg:              tt.fields.eg,
				ctx:             tt.fields.ctx,
				cancel:          tt.fields.cancel,
				peerKnowledge:   tt.fields.peerKnowledge,
				peerConfig:      tt.fields.peerConfig,
				signer:          tt.fields.signer,
				printsRequested: tt.fields.printsRequested,
			}
			s.configurePeersOnce(tt.args.newFacts, tt.args.dev, tt.args.startTime, tt.args.now)

			// TODO: check mocks
		})
	}
}

func deviceWithPeerSimple(key wgtypes.Key) *wgtypes.Device {
	return &wgtypes.Device{
		Peers: []wgtypes.Peer{
			wgtypes.Peer{
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

type configBuilder config.Server

func buildConfig(name string) *configBuilder {
	ret := &configBuilder{}
	ret.Iface = name
	return ret
}
func (c *configBuilder) withPeer(key wgtypes.Key, peer *config.Peer) *configBuilder {
	if c == nil {
		c = &configBuilder{}
	}
	if c.Peers == nil {
		c.Peers = make(config.Peers)
	}
	c.Peers[key] = peer
	return c
}

func (c *configBuilder) Build() *config.Server {
	return (*config.Server)(c)
}

func TestLinkServer_deletePeers(t *testing.T) {
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
							wgtypes.PeerConfig{
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
							wgtypes.PeerConfig{
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
							wgtypes.PeerConfig{
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
		// TODO: don't delete when local is AddPeer
		// TODO: don't delete when remote is statically valid
		// TODO: don't delete when DelPeer is offline
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
			err := s.deletePeers(tt.args.dev, tt.args.removePeer)
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
		bootID          uuid.UUID
		stateAccess     *sync.Mutex
		config          *config.Server
		net             networking.Environment
		conn            *net.UDPConn
		addr            net.UDPAddr
		ctrl            internal.WgClient
		eg              *errgroup.Group
		ctx             context.Context
		cancel          context.CancelFunc
		peerKnowledge   *peerKnowledgeSet
		peerConfig      *peerConfigSet
		signer          *signing.Signer
		printsRequested *int32
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
				bootID:          tt.fields.bootID,
				stateAccess:     tt.fields.stateAccess,
				config:          tt.fields.config,
				net:             tt.fields.net,
				conn:            tt.fields.conn,
				addr:            tt.fields.addr,
				ctrl:            tt.fields.ctrl,
				eg:              tt.fields.eg,
				ctx:             tt.fields.ctx,
				cancel:          tt.fields.cancel,
				peerKnowledge:   tt.fields.peerKnowledge,
				peerConfig:      tt.fields.peerConfig,
				signer:          tt.fields.signer,
				printsRequested: tt.fields.printsRequested,
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
