package config

import (
	"net"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/trust"

	"github.com/stretchr/testify/assert"
)

func Test_configEvaluator_TrustLevel(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)
	k1u := &net.UDPAddr{IP: autopeer.AutoAddress(k1)}

	u1 := testutils.RandUDP4Addr(t)

	// type fields struct {
	// 	Peers    Peers
	// 	ipToPeer map[[net.IPv6len]byte]wgtypes.Key
	// }
	type args struct {
		f      *fact.Fact
		source net.UDPAddr
	}
	tests := []struct {
		name string
		// fields fields
		peers Peers
		args  args
		want  *trust.Level
	}{
		{
			"no known peers",
			Peers{},
			args{source: *u1},
			nil,
		},
		{
			"known peer un-configured",
			Peers{k1: &Peer{}},
			args{source: *k1u},
			nil,
		},
		{
			"known peer configured",
			Peers{k1: &Peer{Trust: trustPtr(trust.AddPeer)}},
			args{source: *k1u},
			trustPtr(trust.AddPeer),
		},
		{
			"unknown peer",
			Peers{k2: &Peer{Trust: trustPtr(trust.DelPeer)}},
			args{source: *k1u},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// c := &configEvaluator{
			// 	Peers:    tt.fields.Peers,
			// 	ipToPeer: tt.fields.ipToPeer,
			// }
			c := CreateTrustEvaluator(tt.peers)
			got := c.TrustLevel(tt.args.f, tt.args.source)
			assert.Equal(t, tt.want, got)
		})
	}
}
