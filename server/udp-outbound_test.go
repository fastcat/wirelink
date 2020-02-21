package server

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/mocks"
	netmocks "github.com/fastcat/wirelink/internal/networking/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/signing"
	"github.com/fastcat/wirelink/trust"
	"github.com/fastcat/wirelink/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinkServer_shouldSendTo(t *testing.T) {
	k1 := testutils.MustKey(t)
	ep1 := testutils.RandUDP4Addr(t)
	routerNet := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	now := time.Now()

	type fields struct {
		config *config.Server
	}
	type args struct {
		p *wgtypes.Peer
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   sendLevel
	}{
		{
			"send nothing to unreachable peer",
			fields{
				&config.Server{},
			},
			args{
				&wgtypes.Peer{},
			},
			sendNothing,
		},
		{
			"send everything to trusted peer",
			fields{&config.Server{Peers: config.Peers{
				k1: &config.Peer{Trust: trust.Ptr(trust.AllowedIPs)},
			}}},
			args{
				&wgtypes.Peer{PublicKey: k1, Endpoint: ep1},
			},
			sendFacts,
		},
		{
			"send everything to router",
			fields{&config.Server{}},
			args{
				&wgtypes.Peer{
					PublicKey:  k1,
					Endpoint:   ep1,
					AllowedIPs: []net.IPNet{routerNet},
				},
			},
			sendFacts,
		},
		{
			"send everything to fact exchanger",
			fields{&config.Server{Peers: config.Peers{
				k1: &config.Peer{FactExchanger: true},
			}}},
			args{
				&wgtypes.Peer{
					PublicKey: k1,
					Endpoint:  ep1,
				},
			},
			sendFacts,
		},
		{
			"send everything when self is chatty and peer is healthy",
			fields{&config.Server{Chatty: true}},
			args{
				&wgtypes.Peer{
					PublicKey:         k1,
					Endpoint:          ep1,
					LastHandshakeTime: now,
				},
			},
			sendFacts,
		},
		{
			"send everything when self is router and peer is healthy",
			fields{&config.Server{IsRouterNow: true}},
			args{
				&wgtypes.Peer{
					PublicKey:         k1,
					Endpoint:          ep1,
					LastHandshakeTime: now,
				},
			},
			sendFacts,
		},
		{
			"send ping when self is chatty and peer is unhealthy",
			fields{&config.Server{Chatty: true}},
			args{
				&wgtypes.Peer{
					PublicKey: k1,
					Endpoint:  ep1,
				},
			},
			sendPing,
		},
		{
			"send ping when self is router and peer is unhealthy",
			fields{&config.Server{IsRouterNow: true}},
			args{
				&wgtypes.Peer{
					PublicKey: k1,
					Endpoint:  ep1,
				},
			},
			sendPing,
		},
		{
			"send ping when both are normal and healthy",
			fields{&config.Server{}},
			args{
				&wgtypes.Peer{
					PublicKey:         k1,
					Endpoint:          ep1,
					LastHandshakeTime: now,
				},
			},
			sendPing,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				config:      tt.fields.config,
				stateAccess: &sync.Mutex{},
			}
			assert.Equal(t, tt.want, s.shouldSendTo(tt.args.p))
		})
	}
}

func TestLinkServer_broadcastFacts(t *testing.T) {
	bootID := uuid.Must(uuid.NewRandom())
	wgIface := fmt.Sprintf("wg%d", rand.Int())
	port := rand.Intn(65536)

	localPrivateKey, localPublicKey := testutils.MustKeyPair(t)
	_, remotePublicKey := testutils.MustKeyPair(t)

	localEP := testutils.RandUDP4Addr(t)
	remoteEP1 := testutils.RandUDP4Addr(t)

	now := time.Now()
	timeout := time.Second
	expires := now.Add(DefaultFactTTL)
	expired := now.Add(-DefaultFactTTL)

	expectSWD := func(conn *netmocks.UDPConn) *mock.Call {
		return conn.On("SetWriteDeadline", now.Add(timeout)).Return(nil)
	}
	expectSGVOf := func(t *testing.T, conn *netmocks.UDPConn, facts ...*fact.Fact) *mock.Call {
		sgv := &fact.SignedGroupValue{}
		for _, f := range facts {
			sgv.InnerBytes = append(sgv.InnerBytes, util.MustBytes(f.MarshalBinaryNow(now))...)
		}
		dest := &net.UDPAddr{
			IP:   autopeer.AutoAddress(remotePublicKey),
			Port: port,
			Zone: wgIface,
		}
		sgvFact := &fact.Fact{
			Attribute: fact.AttributeSignedGroup,
			Subject:   &fact.PeerSubject{Key: localPublicKey},
			Value:     sgv,
			Expires:   now, // SGV facts have instant-expiration
		}
		sgvBytes := util.MustBytes(sgvFact.MarshalBinaryNow(now))
		checkSGVFactBytes := func(packet []byte) bool {
			f := &fact.Fact{}
			err := f.DecodeFrom(0, now, bytes.NewBuffer(packet))
			if err != nil {
				return false
			}
			pSGV, pvIsSGV := f.Value.(*fact.SignedGroupValue)
			if !pvIsSGV {
				return false
			}
			match := f.Attribute == sgvFact.Attribute &&
				reflect.DeepEqual(f.Subject, sgvFact.Subject) &&
				f.Expires == sgvFact.Expires &&
				pvIsSGV &&
				bytes.Equal(pSGV.InnerBytes, sgv.InnerBytes)
			if !match {
				inner, err := pSGV.ParseInner(now)
				if err != nil {
					return false
				}
				t.Logf("Failed matching %v against expected %v", inner, facts)
			}
			return match
		}
		return conn.On(
			"WriteToUDP",
			mock.MatchedBy(checkSGVFactBytes),
			dest,
		).Return(len(sgvBytes), nil)
	}

	type fields struct {
		bootID        uuid.UUID
		config        *config.Server
		conn          func(*testing.T) *netmocks.UDPConn
		addr          net.UDPAddr
		ctrl          func(*testing.T) *mocks.WgClient
		peerKnowledge *peerKnowledgeSet
		signer        *signing.Signer
	}
	type args struct {
		self    wgtypes.Key
		peers   []wgtypes.Peer
		facts   []*fact.Fact
		now     time.Time
		timeout time.Duration
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantPacketsSent int
		wantSendErrors  []error
	}{
		{
			"empty",
			fields{
				bootID,
				&config.Server{
					Iface: wgIface,
				},
				func(t *testing.T) *netmocks.UDPConn {
					ret := &netmocks.UDPConn{}
					expectSWD(ret)
					return ret
				},
				net.UDPAddr{
					Port: port,
					Zone: wgIface,
				},
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					return ret
				},
				newPKS(),
				signing.New(&localPrivateKey),
			},
			args{
				localPublicKey,
				[]wgtypes.Peer{},
				[]*fact.Fact{},
				now,
				timeout,
			},
			0,
			nil,
		},
		{
			"send alive to one peer",
			fields{
				bootID,
				&config.Server{
					Iface: wgIface,
				},
				func(t *testing.T) *netmocks.UDPConn {
					ret := &netmocks.UDPConn{}
					expectSWD(ret)
					expectSGVOf(t, ret, facts.AliveFactFull(&localPublicKey, expires, bootID))
					return ret
				},
				net.UDPAddr{
					Port: port,
					Zone: wgIface,
				},
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					return ret
				},
				newPKS(),
				signing.New(&localPrivateKey),
			},
			args{
				localPublicKey,
				[]wgtypes.Peer{{
					PublicKey:         remotePublicKey,
					Endpoint:          remoteEP1,
					LastHandshakeTime: now,
				}},
				[]*fact.Fact{},
				now,
				timeout,
			},
			1,
			nil,
		},
		{
			"send self ep to FE peer",
			fields{
				bootID,
				&config.Server{
					Iface: wgIface,
					Peers: config.Peers{
						remotePublicKey: &config.Peer{
							FactExchanger: true,
						},
					},
				},
				func(t *testing.T) *netmocks.UDPConn {
					ret := &netmocks.UDPConn{}
					expectSWD(ret)
					expectSGVOf(t, ret,
						facts.EndpointFactFull(localEP, &localPublicKey, expires),
						facts.AliveFactFull(&localPublicKey, expires, bootID),
					)
					return ret
				},
				net.UDPAddr{
					Port: port,
					Zone: wgIface,
				},
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					return ret
				},
				newPKS(),
				signing.New(&localPrivateKey),
			},
			args{
				localPublicKey,
				[]wgtypes.Peer{{
					PublicKey:         remotePublicKey,
					Endpoint:          remoteEP1,
					LastHandshakeTime: now,
				}},
				[]*fact.Fact{
					facts.EndpointFactFull(localEP, &localPublicKey, expires),
				},
				now,
				timeout,
			},
			1,
			nil,
		},
		{
			"send nothing to peer that knows we're alive",
			fields{
				bootID,
				&config.Server{
					Iface: wgIface,
				},
				func(t *testing.T) *netmocks.UDPConn {
					ret := &netmocks.UDPConn{}
					expectSWD(ret)
					return ret
				},
				net.UDPAddr{
					Port: port,
					Zone: wgIface,
				},
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					return ret
				},
				newPKS().mockPeerKnowsLocalAlive(&remotePublicKey, &localPublicKey, expires, &bootID),
				signing.New(&localPrivateKey),
			},
			args{
				localPublicKey,
				[]wgtypes.Peer{{
					PublicKey:         remotePublicKey,
					Endpoint:          remoteEP1,
					LastHandshakeTime: now,
				}},
				[]*fact.Fact{},
				now,
				timeout,
			},
			0,
			nil,
		},
		{
			"send self ep to FE peer that forgot it",
			fields{
				bootID,
				&config.Server{
					Iface: wgIface,
					Peers: config.Peers{
						remotePublicKey: &config.Peer{
							FactExchanger: true,
						},
					},
				},
				func(t *testing.T) *netmocks.UDPConn {
					ret := &netmocks.UDPConn{}
					expectSWD(ret)
					expectSGVOf(t, ret,
						facts.EndpointFactFull(localEP, &localPublicKey, expires),
						facts.AliveFactFull(&localPublicKey, expires, bootID),
					)
					return ret
				},
				net.UDPAddr{
					Port: port,
					Zone: wgIface,
				},
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					return ret
				},
				newPKS().mockPeerKnowsLocalAlive(
					&remotePublicKey, &localPublicKey, expired, &bootID,
				).mockPeerKnows(
					&remotePublicKey, facts.EndpointFactFull(localEP, &localPublicKey, expired),
				),
				signing.New(&localPrivateKey),
			},
			args{
				localPublicKey,
				[]wgtypes.Peer{{
					PublicKey:         remotePublicKey,
					Endpoint:          remoteEP1,
					LastHandshakeTime: now,
				}},
				[]*fact.Fact{
					facts.EndpointFactFull(localEP, &localPublicKey, expires),
				},
				now,
				timeout,
			},
			1,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.fields.conn(t)
			conn.Test(t)
			ctrl := tt.fields.ctrl(t)
			ctrl.Test(t)
			s := &LinkServer{
				bootID:        tt.fields.bootID,
				config:        tt.fields.config,
				conn:          conn,
				addr:          tt.fields.addr,
				ctrl:          ctrl,
				peerKnowledge: tt.fields.peerKnowledge,
				signer:        tt.fields.signer,

				stateAccess: &sync.Mutex{},

				FactTTL:     DefaultFactTTL,
				ChunkPeriod: DefaultChunkPeriod,
			}
			gotPacketsSent, gotSendErrors := s.broadcastFacts(tt.args.self, tt.args.peers, tt.args.facts, tt.args.now, tt.args.timeout)
			assert.Equal(t, tt.wantPacketsSent, gotPacketsSent)
			assert.Equal(t, tt.wantSendErrors, gotSendErrors)
			conn.AssertExpectations(t)
			ctrl.AssertExpectations(t)
		})
	}
}
