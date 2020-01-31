package peerfacts

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	factutils "github.com/fastcat/wirelink/internal/testutils/facts"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalFacts(t *testing.T) {
	now := time.Now()
	ttl := time.Minute
	expires := now.Add(ttl)
	longLongAgo := now.Add(time.Duration(-5-rand.Intn(10)) * time.Minute)

	k1 := testutils.MustKey(t)

	u1 := testutils.RandUDP4Addr(t)
	u2 := testutils.RandUDP6Addr(t)
	n1 := testutils.RandIPNet(t, net.IPv4len, nil, nil, 24)
	n2 := testutils.RandIPNet(t, net.IPv6len, nil, nil, 64)
	n3 := testutils.RandIPNet(t, net.IPv6len, []byte{0xfe, 0x80}, nil, 128)

	type args struct {
		peer           *wgtypes.Peer
		ttl            time.Duration
		trustLocalAIPs bool
		now            time.Time
	}
	tests := []struct {
		name    string
		args    args
		wantRet []*fact.Fact
		wantErr bool
	}{
		{
			"no local knowledge",
			args{
				&wgtypes.Peer{},
				ttl,
				true,
				now,
			},
			nil,
			false,
		},
		{
			"dead peer, one endpoint",
			args{
				&wgtypes.Peer{
					PublicKey:         k1,
					LastHandshakeTime: longLongAgo,
					Endpoint:          u1,
				},
				ttl,
				false,
				now,
			},
			nil,
			false,
		},
		{
			"live peer, v4 endpoint",
			args{
				&wgtypes.Peer{
					PublicKey:         k1,
					LastHandshakeTime: now,
					Endpoint:          u1,
				},
				ttl,
				false,
				now,
			},
			[]*fact.Fact{
				factutils.EndpointFactFull(u1, &k1, expires),
			},
			false,
		},
		{
			"live peer, v6 endpoint",
			args{
				&wgtypes.Peer{
					PublicKey:         k1,
					LastHandshakeTime: now,
					Endpoint:          u2,
				},
				ttl,
				false,
				now,
			},
			[]*fact.Fact{
				factutils.EndpointFactFull(u2, &k1, expires),
			},
			false,
		},
		{
			"dead peer, mixed AIPs",
			args{
				&wgtypes.Peer{
					PublicKey:  k1,
					Endpoint:   u1,
					AllowedIPs: []net.IPNet{n1, n2, n3},
				},
				ttl,
				true,
				now,
			},
			[]*fact.Fact{
				factutils.AllowedIPFactFull(n1, &k1, expires),
				factutils.AllowedIPFactFull(n2, &k1, expires),
			},
			false,
		},
		{
			"live peer, mixed AIPs",
			args{
				&wgtypes.Peer{
					PublicKey:         k1,
					LastHandshakeTime: now,
					Endpoint:          u1,
					AllowedIPs:        []net.IPNet{n1, n2, n3},
				},
				ttl,
				true,
				now,
			},
			[]*fact.Fact{
				factutils.EndpointFactFull(u1, &k1, expires),
				factutils.AllowedIPFactFull(n1, &k1, expires),
				factutils.AllowedIPFactFull(n2, &k1, expires),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRet, err := LocalFacts(tt.args.peer, tt.args.ttl, tt.args.trustLocalAIPs, tt.args.now)
			if tt.wantErr {
				require.NotNil(t, err, "LocalFacts() error")
			} else {
				require.Nil(t, err, "LocalFacts() error")
			}
			assert.Equal(t, tt.wantRet, gotRet)
		})
	}
}
