package apply

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_EnsurePeerAutoIP_Rebuild(t *testing.T) {
	peer := makePeer(t)
	autoaddr := autopeer.AutoAddressNet(peer.PublicKey)
	peer.AllowedIPs = append(peer.AllowedIPs, autoaddr)

	pcfg := &wgtypes.PeerConfig{
		PublicKey:         peer.PublicKey,
		ReplaceAllowedIPs: true,
	}

	pcfg, added := EnsurePeerAutoIP(peer, pcfg)

	// re-adding shouldn't be logged
	assert.False(t, added)
	assert.Contains(t, pcfg.AllowedIPs, autoaddr)
}

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
		ctrl *mocks.WgClient
		dev  *wgtypes.Device
	}
	tests := []struct {
		name    string
		args    args
		setup   func(args)
		want    int
		wantErr bool
	}{
		{
			"no peers no-op",
			args{
				ctrl: nil,
				dev:  &wgtypes.Device{},
			},
			nil,
			0,
			false,
		},
		{
			"one peer to configure",
			args{
				ctrl: &mocks.WgClient{},
				dev: &wgtypes.Device{
					Name: iface,
					Peers: []wgtypes.Peer{
						wgtypes.Peer{
							PublicKey: k1,
						},
					},
				},
			},
			func(a args) {
				// setup the mock expectations
				a.ctrl.On("ConfigureDevice", iface, wgtypes.Config{
					Peers: []wgtypes.PeerConfig{
						wgtypes.PeerConfig{
							PublicKey:         k1,
							ReplaceAllowedIPs: false,
							AllowedIPs:        []net.IPNet{k1aip},
						},
					},
				}).Return(nil)
			},
			1,
			false,
		},
		{
			"two peers, one to configure",
			args{
				ctrl: &mocks.WgClient{},
				dev: &wgtypes.Device{
					Name: iface,
					Peers: []wgtypes.Peer{
						wgtypes.Peer{
							PublicKey:  k1,
							AllowedIPs: []net.IPNet{k1aip},
						},
						wgtypes.Peer{
							PublicKey: k2,
						},
					},
				},
			},
			func(a args) {
				// setup the mock expectations
				a.ctrl.On("ConfigureDevice", iface, wgtypes.Config{
					Peers: []wgtypes.PeerConfig{
						wgtypes.PeerConfig{
							PublicKey:         k2,
							ReplaceAllowedIPs: false,
							AllowedIPs:        []net.IPNet{k2aip},
						},
					},
				}).Return(nil)
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
						wgtypes.Peer{
							PublicKey:  k1,
							AllowedIPs: []net.IPNet{k1aip},
						},
					},
				},
			},
			nil,
			0,
			false,
		},
		{
			"configuration failure",
			args{
				ctrl: &mocks.WgClient{},
				dev: &wgtypes.Device{
					Name: iface,
					Peers: []wgtypes.Peer{
						wgtypes.Peer{
							PublicKey: k1,
						},
					},
				},
			},
			func(a args) {
				a.ctrl.On("ConfigureDevice", iface, wgtypes.Config{
					Peers: []wgtypes.PeerConfig{
						wgtypes.PeerConfig{
							PublicKey:         k1,
							ReplaceAllowedIPs: false,
							AllowedIPs:        []net.IPNet{k1aip},
						},
					},
				}).Return(errors.New("mocked device error"))
			},
			0,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(tt.args)
			}
			got, err := EnsurePeersAutoIP(tt.args.ctrl, tt.args.dev)
			if tt.args.ctrl != nil {
				tt.args.ctrl.AssertExpectations(t)
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
