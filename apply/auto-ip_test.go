package apply

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
