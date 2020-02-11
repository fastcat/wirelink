package peerfacts

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/networking/mocks"
	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDeviceFacts(t *testing.T) {
	now := time.Now()
	n1 := fmt.Sprintf("wg%d", rand.Int31())
	n2 := fmt.Sprintf("eth%d", rand.Int31())
	n3 := fmt.Sprintf("veth%d", rand.Int31())
	k1 := testutils.MustKey(t)
	ipn1 := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	ipn2 := testutils.RandIPNet(t, net.IPv6len, []byte{0x20}, nil, 64)
	p1 := rand.Intn(65535)

	type args struct {
		dev    *wgtypes.Device
		ttl    time.Duration
		config *config.Server
		env    func(*testing.T) *mocks.Environment
	}
	tests := []struct {
		name    string
		args    args
		wantRet []*fact.Fact
		wantErr bool
	}{
		{
			"simple ipv4 interface, not router",
			args{
				dev: &wgtypes.Device{
					Name:       n1,
					PublicKey:  k1,
					ListenPort: p1,
				},
				ttl: time.Minute,
				config: &config.Server{
					IsRouterNow: false,
				},
				env: func(t *testing.T) *mocks.Environment {
					ret := &mocks.Environment{}
					ret.WithSimpleInterfaces(map[string]net.IPNet{
						n2: ipn1,
					})
					return ret
				},
			},
			[]*fact.Fact{
				&fact.Fact{
					Attribute: fact.AttributeEndpointV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPPortValue{IP: ipn1.IP, Port: p1},
					Expires:   now.Add(time.Minute),
				},
			},
			false,
		},
		{
			"complex multi-address interface, not router",
			args{
				dev: &wgtypes.Device{
					Name:       n1,
					PublicKey:  k1,
					ListenPort: p1,
				},
				ttl: time.Minute,
				config: &config.Server{
					IsRouterNow: false,
				},
				env: func(t *testing.T) *mocks.Environment {
					ret := &mocks.Environment{}
					iface := ret.WithInterface(n2)
					iface.WithAddrs(
						net.IPNet{
							IP:   net.IPv4(127, 0, 0, 1),
							Mask: net.CIDRMask(8, 32),
						},
						ipn1,
						ipn2,
					)
					return ret
				},
			},
			[]*fact.Fact{
				&fact.Fact{
					Attribute: fact.AttributeEndpointV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPPortValue{IP: ipn1.IP, Port: p1},
					Expires:   now.Add(time.Minute),
				},
				&fact.Fact{
					Attribute: fact.AttributeEndpointV6,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPPortValue{IP: ipn2.IP, Port: p1},
					Expires:   now.Add(time.Minute),
				},
			},
			false,
		},
		{
			"excluded interface, not router",
			args{
				dev: &wgtypes.Device{
					Name:       n1,
					PublicKey:  k1,
					ListenPort: p1,
				},
				ttl: time.Minute,
				config: &config.Server{
					IsRouterNow: false,
					HideIfaces:  []string{"veth*"},
				},
				env: func(t *testing.T) *mocks.Environment {
					ret := &mocks.Environment{}
					iface := ret.WithInterface(n2)
					iface.WithAddrs(ipn1)
					iface = ret.WithInterface(n3)
					iface.WithAddrs(ipn2)
					return ret
				},
			},
			[]*fact.Fact{
				&fact.Fact{
					Attribute: fact.AttributeEndpointV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value:     &fact.IPPortValue{IP: ipn1.IP, Port: p1},
					Expires:   now.Add(time.Minute),
				},
			},
			false,
		},
		{
			"local auto-router",
			args{
				dev: &wgtypes.Device{
					Name:      n1,
					PublicKey: k1,
				},
				ttl: time.Minute,
				config: &config.Server{
					IsRouterNow: true,
				},
				env: func(t *testing.T) *mocks.Environment {
					ret := &mocks.Environment{}
					iface := ret.WithInterface(n1)
					iface.WithAddrs(ipn1, ipn2)
					return ret
				},
			},
			[]*fact.Fact{
				&fact.Fact{
					Attribute: fact.AttributeAllowedCidrV4,
					Subject:   &fact.PeerSubject{Key: k1},
					Value: &fact.IPNetValue{IPNet: net.IPNet{
						IP:   ipn1.IP.Mask(ipn1.Mask),
						Mask: ipn1.Mask,
					}},
					Expires: now.Add(time.Minute),
				},
				&fact.Fact{
					Attribute: fact.AttributeAllowedCidrV6,
					Subject:   &fact.PeerSubject{Key: k1},
					Value: &fact.IPNetValue{IPNet: net.IPNet{
						IP:   ipn2.IP.Mask(ipn2.Mask),
						Mask: ipn2.Mask,
					}},
					Expires: now.Add(time.Minute),
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.args.env(t)
			env.WithKnownInterfaces()
			env.Test(t)
			gotRet, err := DeviceFacts(tt.args.dev, now, tt.args.ttl, tt.args.config, env)
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
