package config

import (
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/trust"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mostly for experimenting with what errors the `net` package provides
// it seems that basically everything is a DNSError other than the empty string
func Test_DnsErrors(t *testing.T) {
	// this one _ought_ to give some kind of parse or range error ... but it doesn't
	ips, err := net.LookupIP("256.256.256.256") // gives no such host
	assert.NotNil(t, err)
	assert.Len(t, ips, 0)
	assert.IsType(t, &net.DNSError{}, err)
}

func TestPeerData_Parse(t *testing.T) {
	k := testutils.MustKey(t)

	type fields struct {
		PublicKey     string
		Name          string
		Trust         string
		FactExchanger bool
		Endpoints     []string
		AllowedIPs    []string
		Basic         bool
	}
	tests := []struct {
		name     string
		fields   fields
		wantKey  wgtypes.Key
		wantPeer Peer
		wantErr  bool
	}{
		{"bad key", fields{PublicKey: "xyzzy"}, wgtypes.Key{}, Peer{}, true},
		{"bad trust", fields{PublicKey: k.String(), Trust: "xyzzy"}, k, Peer{}, true},
		{
			"simple without trust",
			fields{
				PublicKey: k.String(),
				Name:      "xyzzy",
			},
			k,
			Peer{
				Name:       "xyzzy",
				Trust:      nil,
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
			},
			false,
		},
		{
			"simple with trust",
			fields{
				PublicKey: k.String(),
				Name:      "xyzzy",
				Trust:     trust.Names[trust.Membership],
			},
			k,
			Peer{
				Name:       "xyzzy",
				Trust:      trust.Ptr(trust.Membership),
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
			},
			false,
		},
		{
			"bad endpoint: no colon",
			fields{
				PublicKey: k.String(),
				Endpoints: []string{"localhost"},
			},
			k,
			Peer{
				Endpoints: []PeerEndpoint{},
			},
			true,
		},
		{
			"bad endpoint: bad named service",
			fields{
				PublicKey: k.String(),
				Endpoints: []string{"localhost:xyzzy"},
			},
			k,
			Peer{
				Endpoints: []PeerEndpoint{},
			},
			true,
		},
		{
			"bad endpoint: bad numbered service",
			fields{
				PublicKey: k.String(),
				Endpoints: []string{"localhost:65536"},
			},
			k,
			Peer{
				Endpoints: []PeerEndpoint{},
			},
			true,
		},
		{
			"good endpoint: good named service",
			fields{
				PublicKey: k.String(),
				// the port (service) name here has to be a UDP one, can't use something like "http"
				Endpoints: []string{"localhost:chargen"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{PeerEndpoint{"localhost", 19}},
				AllowedIPs: []net.IPNet{},
			},
			false,
		},
		{
			"good endpoint: good numbered service",
			fields{
				PublicKey: k.String(),
				Endpoints: []string{"localhost:80"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{PeerEndpoint{"localhost", 80}},
				AllowedIPs: []net.IPNet{},
			},
			false,
		},
		{
			"ok endpoint: unresolved hostname",
			fields{
				PublicKey: k.String(),
				Endpoints: []string{"example.invalid:80"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{PeerEndpoint{"example.invalid", 80}},
				AllowedIPs: []net.IPNet{},
			},
			false,
		},
		{
			"bad allowedip: garbage",
			fields{
				PublicKey:  k.String(),
				AllowedIPs: []string{"xyzzy"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
			},
			true,
		},
		{
			"bad allowedip: ipv4 octet range",
			fields{
				PublicKey:  k.String(),
				AllowedIPs: []string{"123.456.789.012/16"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
			},
			true,
		},
		{
			"bad allowedip: ipv4 mask range",
			fields{
				PublicKey:  k.String(),
				AllowedIPs: []string{"1.2.3.4/33"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
			},
			true,
		},
		{
			"bad allowedip: ipv6 octet range",
			fields{
				PublicKey: k.String(),
				// cspell: disable-next-line
				AllowedIPs: []string{"fe80::1234:5678:9abc:defg/128"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
			},
			true,
		},
		{
			"bad allowedip: ipv6 mask range",
			fields{
				PublicKey:  k.String(),
				AllowedIPs: []string{"fe80::1234:5678:9abc:def0/129"},
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
			},
			true,
		},
		{
			"good allowedip: ipv4 and ipv6",
			fields{
				PublicKey: k.String(),
				AllowedIPs: []string{
					"2001:db8:100::0/64",
					"2001:db8:200::1/128",
					"192.0.2.0/24",
					"198.51.100.1/32",
				},
			},
			k,
			Peer{
				Endpoints: []PeerEndpoint{},
				AllowedIPs: []net.IPNet{
					testutils.MakeIPv6Net([]byte{0x20, 0x01, 0x0d, 0xb8, 0x01}, nil, 64),
					testutils.MakeIPv6Net([]byte{0x20, 0x01, 0x0d, 0xb8, 0x02}, []byte{0x01}, 128),
					testutils.MakeIPv4Net(192, 0, 2, 0, 24),
					testutils.MakeIPv4Net(198, 51, 100, 1, 32),
				},
			},
			false,
		},
		{
			"basic peer",
			fields{
				PublicKey: k.String(),
				Basic:     true,
			},
			k,
			Peer{
				Endpoints:  []PeerEndpoint{},
				AllowedIPs: []net.IPNet{},
				Basic:      true,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PeerData{
				PublicKey:     tt.fields.PublicKey,
				Name:          tt.fields.Name,
				Trust:         tt.fields.Trust,
				FactExchanger: tt.fields.FactExchanger,
				Endpoints:     tt.fields.Endpoints,
				AllowedIPs:    tt.fields.AllowedIPs,
				Basic:         tt.fields.Basic,
			}
			gotKey, gotPeer, err := p.Parse()

			if tt.wantErr {
				require.NotNil(t, err, "PeerData.Parse() error")
			} else {
				require.Nil(t, err, "PeerData.Parse() error")
			}

			assert.Equal(t, tt.wantKey, gotKey)
			assert.Equal(t, tt.wantPeer, gotPeer)
		})
	}
}
