package apply

import (
	"math/rand"
	"net"

	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func makeIPNet(t *testing.T) net.IPNet {
	return net.IPNet{
		IP:   testutils.MustRandBytes(t, make([]byte, net.IPv4len)),
		Mask: net.CIDRMask(1+rand.Intn(8*net.IPv4len), 8*net.IPv4len),
	}
}

func aipFact(key wgtypes.Key, aip net.IPNet) (aipFact *fact.Fact) {
	return &fact.Fact{
		Subject:   &fact.PeerSubject{Key: key},
		Attribute: fact.AttributeAllowedCidrV4,
		Value:     &fact.IPNetValue{IPNet: aip},
	}
}

func TestEnsureAllowedIPs(t *testing.T) {
	k := testutils.MustKey(t)
	autoIP := autopeer.AutoAddressNet(k)
	aip1 := makeIPNet(t)
	aip2 := makeIPNet(t)
	aip3 := makeIPNet(t)

	type args struct {
		peer             *wgtypes.Peer
		facts            []*fact.Fact
		cfg              *wgtypes.PeerConfig
		allowDeconfigure bool
	}
	tests := []struct {
		name string
		args args
		want *wgtypes.PeerConfig
	}{
		{
			"nil",
			args{
				peer: &wgtypes.Peer{PublicKey: k},
			},
			nil,
		},
		{
			"add one",
			args{
				peer: &wgtypes.Peer{
					PublicKey: k,
				},
				facts: []*fact.Fact{aipFact(k, aip1)},
			},
			&wgtypes.PeerConfig{
				PublicKey:  k,
				AllowedIPs: []net.IPNet{aip1},
			},
		},
		{
			"remove only",
			args{
				peer: &wgtypes.Peer{
					PublicKey:  k,
					AllowedIPs: []net.IPNet{aip1, autoIP},
				},
				allowDeconfigure: true,
			},
			&wgtypes.PeerConfig{
				PublicKey:         k,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{autoIP},
			},
		},
		{
			"replace only",
			args{
				peer: &wgtypes.Peer{
					PublicKey:  k,
					AllowedIPs: []net.IPNet{aip1},
				},
				facts:            []*fact.Fact{aipFact(k, aip2)},
				allowDeconfigure: true,
			},
			&wgtypes.PeerConfig{
				PublicKey:         k,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{autoIP, aip2},
			},
		},
		{
			"replace one",
			args{
				peer: &wgtypes.Peer{
					PublicKey:  k,
					AllowedIPs: []net.IPNet{autoIP, aip1, aip2},
				},
				facts: []*fact.Fact{
					aipFact(k, aip1),
					aipFact(k, aip3),
				},
				allowDeconfigure: true,
			},
			&wgtypes.PeerConfig{
				PublicKey:         k,
				ReplaceAllowedIPs: true,
				AllowedIPs:        []net.IPNet{autoIP, aip1, aip3},
			},
		},
		{
			"keeps already-adding aip",
			args{
				peer: &wgtypes.Peer{PublicKey: k},
				facts: []*fact.Fact{
					aipFact(k, aip2),
				},
				cfg: &wgtypes.PeerConfig{
					PublicKey:  k,
					AllowedIPs: []net.IPNet{aip1},
				},
			},
			&wgtypes.PeerConfig{
				PublicKey:  k,
				AllowedIPs: []net.IPNet{aip1, aip2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EnsureAllowedIPs(tt.args.peer, tt.args.facts, tt.args.cfg, tt.args.allowDeconfigure)
			// have to sort the AIP lists for the equality to work
			if got != nil {
				testutils.SortIPNetSlice(got.AllowedIPs)
			}
			if tt.want != nil {
				testutils.SortIPNetSlice(tt.want.AllowedIPs)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
