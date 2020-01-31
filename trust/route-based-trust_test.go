package trust

import (
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_routeBasedTrust_TrustLevel(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)
	k3 := testutils.MustKey(t)

	peerAddr := func(k wgtypes.Key) net.UDPAddr {
		return net.UDPAddr{IP: autopeer.AutoAddress(k), Port: rand.Intn(65535)}
	}
	factAbout := func(k wgtypes.Key) *fact.Fact {
		return &fact.Fact{
			Subject: &fact.PeerSubject{Key: k},
		}
	}
	peerList := func(ks ...wgtypes.Key) []wgtypes.Peer {
		ret := make([]wgtypes.Peer, len(ks))
		for i, k := range ks {
			ret[i] = wgtypes.Peer{PublicKey: k}
		}
		return ret
	}
	routerList := func(ks ...wgtypes.Key) []wgtypes.Peer {
		ret := make([]wgtypes.Peer, len(ks))
		for i, k := range ks {
			ret[i] = wgtypes.Peer{PublicKey: k, AllowedIPs: []net.IPNet{
				// make sure the top byte isn't something that will fail IsGlobalUnicast
				testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 1+rand.Intn(31)),
			}}
		}
		return ret
	}

	// type fields struct {
	// 	peersByIP  map[[net.IPv6len]byte]*peerWithAddr
	// 	peersByKey map[wgtypes.Key]*peerWithAddr
	// }
	type args struct {
		f      *fact.Fact
		source net.UDPAddr
	}
	mkArgs := func(subject, source wgtypes.Key) args {
		return args{
			factAbout(subject),
			peerAddr(source),
		}
	}
	tests := []struct {
		name string
		// fields fields
		peers []wgtypes.Peer
		args  args
		want  *Level
	}{
		{
			"unknown",
			peerList(k1),
			mkArgs(k2, k3),
			nil,
		},
		{
			"known leaf self info",
			peerList(k1),
			mkArgs(k1, k1),
			trustPtr(Endpoint),
		},
		{
			"known leaf other info",
			peerList(k1),
			mkArgs(k2, k1),
			trustPtr(Endpoint),
		},
		{
			"known router",
			routerList(k1),
			mkArgs(k2, k1),
			trustPtr(AllowedIPs),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// rbt := &routeBasedTrust{
			// 	peersByIP:  tt.fields.peersByIP,
			// 	peersByKey: tt.fields.peersByKey,
			// }
			rbt := CreateRouteBasedTrust(tt.peers)
			got := rbt.TrustLevel(tt.args.f, tt.args.source)
			assert.Equal(t, tt.want, got, "want %v got %v", tt.want, got)
		})
	}
}

func Test_routeBasedTrust_IsKnown(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)

	ksa := func(k wgtypes.Key) struct{ s fact.Subject } {
		return struct{ s fact.Subject }{&fact.PeerSubject{Key: k}}
	}

	// type fields struct {
	// 	peersByIP  map[[net.IPv6len]byte]*peerWithAddr
	// 	peersByKey map[wgtypes.Key]*peerWithAddr
	// }
	type args struct {
		s fact.Subject
	}
	tests := []struct {
		name string
		// fields fields
		peers []wgtypes.Peer
		args  args
		want  bool
	}{
		{"known", []wgtypes.Peer{{PublicKey: k1}}, ksa(k1), true},
		{"unknown", []wgtypes.Peer{{PublicKey: k1}}, ksa(k2), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// rbt := &routeBasedTrust{
			// 	peersByIP:  tt.fields.peersByIP,
			// 	peersByKey: tt.fields.peersByKey,
			// }
			rbt := CreateRouteBasedTrust(tt.peers)
			got := rbt.IsKnown(tt.args.s)
			assert.Equal(t, tt.want, got)
		})
	}
}
