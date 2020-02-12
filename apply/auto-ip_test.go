package apply

import (
	"fmt"
	"math/rand"
	"net"

	"github.com/pkg/errors"

	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestEnsurePeersAutoIP(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)
	k1aip := net.IPNet{
		IP:   autopeer.AutoAddress(k1),
		Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
	}
	k2aip := net.IPNet{
		IP:   autopeer.AutoAddress(k2),
		Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
	}
	iface := fmt.Sprintf("wg%d", rand.Int31())

	type args struct {
		ctrl func(*testing.T) *mocks.WgClient
		dev  *wgtypes.Device
	}
	tests := []struct {
		name    string
		args    args
		want    int
		wantErr bool
	}{
		{
			"no peers no-op",
			args{
				ctrl: nil,
				dev:  &wgtypes.Device{},
			},
			0,
			false,
		},
		{
			"one peer to configure",
			args{
				ctrl: func(t *testing.T) *mocks.WgClient {
					ctrl := &mocks.WgClient{}
					ctrl.On("ConfigureDevice", iface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey:         k1,
								ReplaceAllowedIPs: false,
								AllowedIPs:        []net.IPNet{k1aip},
							},
						},
					}).Return(nil)
					return ctrl
				},
				dev: &wgtypes.Device{
					Name: iface,
					Peers: []wgtypes.Peer{
						{
							PublicKey: k1,
						},
					},
				},
			},
			1,
			false,
		},
		{
			"two peers, one to configure",
			args{
				ctrl: func(t *testing.T) *mocks.WgClient {
					ctrl := &mocks.WgClient{}
					ctrl.On("ConfigureDevice", iface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey:         k2,
								ReplaceAllowedIPs: false,
								AllowedIPs:        []net.IPNet{k2aip},
							},
						},
					}).Return(nil)
					return ctrl
				},
				dev: &wgtypes.Device{
					Name: iface,
					Peers: []wgtypes.Peer{
						{
							PublicKey:  k1,
							AllowedIPs: []net.IPNet{k1aip},
						},
						{
							PublicKey: k2,
						},
					},
				},
			},
			1,
			false,
		},
		{
			"one peer already configured",
			args{
				ctrl: nil,
				dev: &wgtypes.Device{
					Peers: []wgtypes.Peer{
						{
							PublicKey:  k1,
							AllowedIPs: []net.IPNet{k1aip},
						},
					},
				},
			},
			0,
			false,
		},
		{
			"configuration failure",
			args{
				ctrl: func(t *testing.T) *mocks.WgClient {
					ctrl := &mocks.WgClient{}
					ctrl.On("ConfigureDevice", iface, wgtypes.Config{
						Peers: []wgtypes.PeerConfig{
							{
								PublicKey:         k1,
								ReplaceAllowedIPs: false,
								AllowedIPs:        []net.IPNet{k1aip},
							},
						},
					}).Return(errors.New("mocked device error"))
					return ctrl
				},
				dev: &wgtypes.Device{
					Name: iface,
					Peers: []wgtypes.Peer{
						{
							PublicKey: k1,
						},
					},
				},
			},
			0,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ctrl *mocks.WgClient
			if tt.args.ctrl != nil {
				ctrl = tt.args.ctrl(t)
				ctrl.Test(t)
			}
			got, err := EnsurePeersAutoIP(ctrl, tt.args.dev)
			if ctrl != nil {
				ctrl.AssertExpectations(t)
			}
			if tt.wantErr {
				require.NotNil(t, err, "EnsurePeersAutoIP() error")
			} else {
				require.Nil(t, err, "EnsurePeersAutoIP() error")
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEnsurePeerAutoIP(t *testing.T) {
	p1 := &wgtypes.Peer{PublicKey: testutils.MustKey(t)}
	aip1 := autopeer.AutoAddressNet(p1.PublicKey)
	p1.AllowedIPs = append(p1.AllowedIPs, aip1)

	type args struct {
		peer *wgtypes.Peer
		cfg  *wgtypes.PeerConfig
	}
	tests := []struct {
		name           string
		args           args
		wantPeerConfig *wgtypes.PeerConfig
		wantAdded      bool
	}{
		{
			"rebuild",
			args{
				peer: p1,
				cfg: &wgtypes.PeerConfig{
					PublicKey:         p1.PublicKey,
					ReplaceAllowedIPs: true,
				},
			},
			&wgtypes.PeerConfig{
				PublicKey:         p1.PublicKey,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{aip1},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPeerConfig, gotAdded := EnsurePeerAutoIP(tt.args.peer, tt.args.cfg)
			assert.Equal(t, tt.wantPeerConfig, gotPeerConfig, "EnsurePeerAutoIP() peerConfig")
			assert.Equal(t, tt.wantAdded, gotAdded, "EnsurePeerAutoIP() added")
		})
	}
}

func TestOnlyAutoIP(t *testing.T) {
	k1 := testutils.MustKey(t)
	type args struct {
		peer *wgtypes.Peer
		cfg  *wgtypes.PeerConfig
	}
	tests := []struct {
		name string
		args args
		want *wgtypes.PeerConfig
	}{
		{
			"new peer",
			args{
				peer: &wgtypes.Peer{PublicKey: k1},
				cfg:  nil,
			},
			&wgtypes.PeerConfig{
				PublicKey:         k1,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{autopeer.AutoAddressNet(k1)},
			},
		},
		{
			"already being configured",
			args{
				peer: &wgtypes.Peer{PublicKey: k1},
				cfg: &wgtypes.PeerConfig{
					PublicKey:  k1,
					AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(k1)},
				},
			},
			&wgtypes.PeerConfig{
				PublicKey:         k1,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{autopeer.AutoAddressNet(k1)},
			},
		},
		{
			"already configured, no changes",
			args{
				peer: &wgtypes.Peer{
					PublicKey:  k1,
					AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(k1)},
				},
				cfg: nil,
			},
			nil,
		},
		{
			// this behavior is a bit dodgy, and dependent on the method under test
			// only being called from a specific point in the processing chain
			"already configured, no-op change planned",
			args{
				peer: &wgtypes.Peer{
					PublicKey:  k1,
					AllowedIPs: []net.IPNet{autopeer.AutoAddressNet(k1)},
				},
				cfg: &wgtypes.PeerConfig{
					PublicKey: k1,
				},
			},
			&wgtypes.PeerConfig{
				PublicKey: k1,
			},
		},
		{
			"needs rebuild",
			args{
				peer: &wgtypes.Peer{
					PublicKey:  k1,
					AllowedIPs: []net.IPNet{makeIPNet(t)},
				},
				cfg: nil,
			},
			&wgtypes.PeerConfig{
				PublicKey:         k1,
				AllowedIPs:        []net.IPNet{autopeer.AutoAddressNet(k1)},
				ReplaceAllowedIPs: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := OnlyAutoIP(tt.args.peer, tt.args.cfg)
			assert.Equal(t, tt.want, got)
		})
	}
}
