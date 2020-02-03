package server

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/networking/mocks"
	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLinkServer_collectFacts(t *testing.T) {
	now := time.Now()
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)
	ifWg := fmt.Sprintf("wg%d", rand.Int())
	ifEth := fmt.Sprintf("eth%d", rand.Int())
	ipn1 := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	ipn2 := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	ipn3 := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	ipn4 := testutils.RandIPNet(t, net.IPv6len, []byte{0x20}, nil, 64)
	ep1 := testutils.RandUDP4Addr(t)
	ep2 := testutils.RandUDP6Addr(t)
	p1 := rand.Intn(65535)

	type fields struct {
		config     *config.Server
		net        func(*testing.T) *mocks.Environment
		peerConfig *peerConfigSet
	}
	type args struct {
		dev *wgtypes.Device
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantRet []*fact.Fact
		wantErr bool
	}{
		{
			"empty",
			fields{
				&config.Server{},
				func(t *testing.T) *mocks.Environment {
					ret := &mocks.Environment{}
					return ret
				},
				&peerConfigSet{},
			},
			args{&wgtypes.Device{}},
			[]*fact.Fact{},
			false,
		},
		{
			"simple point-to-point (router)",
			fields{
				&config.Server{
					Iface:       ifWg,
					IsRouterNow: true,
				},
				func(t *testing.T) *mocks.Environment {
					ret := &mocks.Environment{}
					ret.WithSimpleInterfaces(map[string]net.IPNet{
						ifWg:  ipn1,
						ifEth: ipn2,
					})
					return ret
				},
				&peerConfigSet{
					psm: &sync.Mutex{},
					peerStates: map[wgtypes.Key]*apply.PeerConfigState{
						k2: &apply.PeerConfigState{},
					},
				},
			},
			args{&wgtypes.Device{
				Name:       ifWg,
				PublicKey:  k1,
				ListenPort: p1,
				Peers: []wgtypes.Peer{
					wgtypes.Peer{
						PublicKey:         k2,
						AllowedIPs:        []net.IPNet{ipn3},
						Endpoint:          ep1,
						LastHandshakeTime: now,
					},
				},
			}},
			[]*fact.Fact{
				// should know the local endpoint
				&fact.Fact{
					Attribute: fact.AttributeEndpointV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPPortValue{IP: ipn2.IP, Port: p1},
					Expires:   now.Add(FactTTL),
				},
				// should know the local AIP
				&fact.Fact{
					Attribute: fact.AttributeAllowedCidrV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value: &fact.IPNetValue{IPNet: net.IPNet{
						IP:   ipn1.IP.Mask(ipn1.Mask),
						Mask: ipn1.Mask,
					}},
					Expires: now.Add(FactTTL),
				},
				// should know the remote endpoint
				&fact.Fact{
					Attribute: fact.AttributeEndpointV4,
					Subject:   &fact.PeerSubject{Key: k2},
					Value:     &fact.IPPortValue{IP: ep1.IP, Port: ep1.Port},
					Expires:   now.Add(FactTTL),
				},
				// should know the remote AIP
				&fact.Fact{
					Attribute: fact.AttributeAllowedCidrV4,
					Subject:   &fact.PeerSubject{Key: k2},
					// we don't mask this one because we expect wg to have done it already
					Value:   &fact.IPNetValue{IPNet: ipn3},
					Expires: now.Add(FactTTL),
				},
			},
			false,
		},
		{
			"static facts",
			fields{
				&config.Server{
					Peers: config.Peers{
						k1: &config.Peer{
							Endpoints: []config.PeerEndpoint{
								config.PeerEndpoint{
									Host: ep1.IP.String(),
									Port: ep1.Port,
								},
								config.PeerEndpoint{
									Host: ep2.IP.String(),
									Port: ep2.Port,
								},
							},
							AllowedIPs: []net.IPNet{ipn1, ipn4},
						},
					},
				},
				func(t *testing.T) *mocks.Environment {
					ret := &mocks.Environment{}
					return ret
				},
				&peerConfigSet{
					psm: &sync.Mutex{},
					peerStates: map[wgtypes.Key]*apply.PeerConfigState{
						k1: &apply.PeerConfigState{},
					},
				},
			},
			args{&wgtypes.Device{}},
			[]*fact.Fact{
				// ipv4 and ipv6 endpoints
				&fact.Fact{
					Attribute: fact.AttributeEndpointV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPPortValue{IP: ep1.IP, Port: ep1.Port},
					Expires:   now.Add(FactTTL),
				},
				&fact.Fact{
					Attribute: fact.AttributeEndpointV6,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPPortValue{IP: ep2.IP, Port: ep2.Port},
					Expires:   now.Add(FactTTL),
				},
				// ipv4 and ipv6 aips
				&fact.Fact{
					Attribute: fact.AttributeAllowedCidrV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPNetValue{IPNet: ipn1},
					Expires:   now.Add(FactTTL),
				},
				&fact.Fact{
					Attribute: fact.AttributeAllowedCidrV6,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPNetValue{IPNet: ipn4},
					Expires:   now.Add(FactTTL),
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.fields.net(t)
			env.WithKnownInterfaces()
			env.Test(t)
			s := &LinkServer{
				config:     tt.fields.config,
				net:        env,
				peerConfig: tt.fields.peerConfig,
			}
			gotRet, err := s.collectFacts(tt.args.dev, now)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}
			// don't be order sensitive
			assert.Len(t, gotRet, len(tt.wantRet))
			for _, f := range tt.wantRet {
				assert.Contains(t, gotRet, f)
			}
			env.AssertExpectations(t)
		})
	}
}
