package detect

import (
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestIsPeerRouter(t *testing.T) {
	type args struct {
		peer *wgtypes.Peer
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"empty", args{&wgtypes.Peer{}}, false},
		{
			"non-routable v4 net",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv4len, []byte{169, 254}, nil, 24),
			}}},
			false,
		},
		{
			"non-routable v4 host",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv4len, []byte{169, 254}, nil, 32),
			}}},
			false,
		},
		{
			"routable v4 net",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24),
			}}},
			true,
		},
		{
			"routable v4 host",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 32),
			}}},
			false,
		},
		{
			"non-routable v6 net",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv6len, []byte{0xfe, 0x80}, nil, 64),
			}}},
			false,
		},
		{
			"non-routable v6 host",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv6len, []byte{0xfe, 0x80}, nil, 128),
			}}},
			false,
		},
		{
			"routable v6 net",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv6len, []byte{0x20}, nil, 64),
			}}},
			true,
		},
		{
			"routable v6 host",
			args{&wgtypes.Peer{AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv4len, []byte{0x20}, nil, 128),
			}}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPeerRouter(tt.args.peer)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsDeviceRouter(t *testing.T) {
	router := func() wgtypes.Peer {
		return wgtypes.Peer{
			AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24),
			},
		}
	}
	leaf := func() wgtypes.Peer {
		return wgtypes.Peer{
			AllowedIPs: []net.IPNet{
				testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 32),
			},
		}
	}
	dev := func(peers ...wgtypes.Peer) *wgtypes.Device {
		return &wgtypes.Device{
			Peers: peers,
		}
	}
	type args struct {
		dev *wgtypes.Device
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"empty", args{dev()}, true},
		{"other leaf", args{dev(leaf())}, true},
		{"other router", args{dev(leaf(), router())}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDeviceRouter(tt.args.dev)
			assert.Equal(t, tt.want, got)
		})
	}
}
