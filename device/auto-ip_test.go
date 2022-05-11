package device

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDevice_EnsurePeersAutoIP(t *testing.T) {
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
			dev := &Device{
				ctrl:  ctrl,
				iface: tt.args.dev.Name,
				state: tt.args.dev,
			}
			got, err := dev.EnsurePeersAutoIP()
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
