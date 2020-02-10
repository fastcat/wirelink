package server

import (
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/trust"

	"github.com/stretchr/testify/assert"

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
		p           *wgtypes.Peer
		factsByPeer map[wgtypes.Key][]*fact.Fact
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
				nil,
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
				nil,
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
				nil,
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
				nil,
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
				nil,
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
				nil,
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
				nil,
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
				nil,
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
				nil,
			},
			sendPing,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LinkServer{
				config: tt.fields.config,
			}
			assert.Equal(t, tt.want, s.shouldSendTo(tt.args.p, tt.args.factsByPeer))
		})
	}
}
