package config

import (
	"net"
	"reflect"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/trust"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPeers_Name(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	type args struct {
		peer wgtypes.Key
	}
	tests := []struct {
		name string
		p    Peers
		args args
		want string
	}{
		{"nil peers", nil, args{k1}, k1.String()},
		{"empty peers", make(Peers), args{k1}, k1.String()},
		{"other peer", Peers{k2: &Peer{Name: "xyzzy"}}, args{k1}, k1.String()},
		{"named peer", Peers{k1: &Peer{Name: "xyzzy"}}, args{k1}, "xyzzy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Name(tt.args.peer); got != tt.want {
				t.Errorf("Peers.Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeers_Trust(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	bothPeers := func(level1, level2 trust.Level) Peers {
		return Peers{k1: &Peer{Trust: &level1}, k2: &Peer{Trust: &level2}}
	}

	type args struct {
		peer wgtypes.Key
		def  trust.Level
	}
	tests := []struct {
		name string
		p    Peers
		args args
		want trust.Level
	}{
		{"nil peers, default trust", nil, args{k1, trust.Untrusted}, trust.Untrusted},
		{"nil peers, high trust", nil, args{k1, trust.DelegateTrust}, trust.DelegateTrust},
		{"other peer", Peers{k2: &Peer{Trust: nil}}, args{k1, trust.Membership}, trust.Membership},
		{"has nil", Peers{k1: &Peer{Trust: nil}}, args{k1, trust.Membership}, trust.Membership},
		{"has value", bothPeers(trust.DelegateTrust, trust.Membership), args{k1, trust.Membership}, trust.DelegateTrust},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p.Trust(tt.args.peer, tt.args.def)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPeers_IsFactExchanger(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	type args struct {
		peer wgtypes.Key
	}
	tests := []struct {
		name string
		p    Peers
		args args
		want bool
	}{
		{"nil peers", nil, args{k1}, false},
		{"empty peers", make(Peers), args{k1}, false},
		{"other peer", Peers{k2: &Peer{FactExchanger: true}}, args{k1}, false},
		{"configured false", Peers{k1: &Peer{FactExchanger: false}, k2: &Peer{FactExchanger: true}}, args{k1}, false},
		{"configured true", Peers{k1: &Peer{FactExchanger: true}, k2: &Peer{FactExchanger: false}}, args{k1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IsFactExchanger(tt.args.peer); got != tt.want {
				t.Errorf("Peers.IsFactExchanger() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeers_IsBasic(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	type args struct {
		peer wgtypes.Key
	}
	tests := []struct {
		name string
		p    Peers
		args args
		want bool
	}{
		{"nil peers", nil, args{k1}, false},
		{"empty peers", make(Peers), args{k1}, false},
		{"other peer", Peers{k2: &Peer{Basic: true}}, args{k1}, false},
		{"configured false", Peers{k1: &Peer{Basic: false}, k2: &Peer{Basic: true}}, args{k1}, false},
		{"configured true", Peers{k1: &Peer{Basic: true}, k2: &Peer{Basic: false}}, args{k1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.IsBasic(tt.args.peer); got != tt.want {
				t.Errorf("Peers.IsBasic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeers_AllowedIPs(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	ipn1 := net.IPNet{IP: net.IPv4(1, 2, 3, 4), Mask: net.CIDRMask(net.IPv4len, net.IPv4len)}
	ipn2 := net.IPNet{IP: net.IPv4(2, 3, 4, 5), Mask: net.CIDRMask(net.IPv4len, net.IPv4len/2)}
	ipn3 := net.IPNet{IP: net.IPv4(3, 4, 5, 6), Mask: net.CIDRMask(net.IPv4len, net.IPv4len/4)}

	type args struct {
		peer wgtypes.Key
	}
	tests := []struct {
		name string
		p    Peers
		args args
		want []net.IPNet
	}{
		{"nil peers", nil, args{k1}, nil},
		{"empty peers", make(Peers), args{k1}, nil},
		{"other peer", Peers{k2: &Peer{AllowedIPs: []net.IPNet{ipn1, ipn2, ipn3}}}, args{k1}, nil},
		{
			"configured",
			Peers{
				k1: &Peer{AllowedIPs: []net.IPNet{ipn1, ipn2}},
				k2: &Peer{AllowedIPs: []net.IPNet{ipn2, ipn3}},
			},
			args{k1},
			[]net.IPNet{ipn1, ipn2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.AllowedIPs(tt.args.peer); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Peers.AllowedIPs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPeers_Endpoints(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	ep1 := PeerEndpoint{"a", 1}
	ep2 := PeerEndpoint{"b", 2}
	ep3 := PeerEndpoint{"c", 3}

	type args struct {
		peer wgtypes.Key
	}
	tests := []struct {
		name string
		p    Peers
		args args
		want []PeerEndpoint
	}{
		{"nil peers", nil, args{k1}, nil},
		{"empty peers", make(Peers), args{k1}, nil},
		{"other peer", Peers{k2: &Peer{Endpoints: []PeerEndpoint{ep1, ep2, ep3}}}, args{k1}, nil},
		{
			"configured",
			Peers{
				k1: &Peer{Endpoints: []PeerEndpoint{ep1, ep2}},
				k2: &Peer{Endpoints: []PeerEndpoint{ep2, ep3}},
			},
			args{k1},
			[]PeerEndpoint{ep1, ep2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p.Endpoints(tt.args.peer)
			assert.Equal(t, tt.want, got, "Peers.Endpoints()")
		})
	}
}
