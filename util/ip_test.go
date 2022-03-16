package util

import (
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeIP(t *testing.T) {
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name string
		args args
		want net.IP
	}{
		{
			"ipv4",
			args{net.ParseIP("1.2.3.4")},
			net.IP([]byte{1, 2, 3, 4}),
		},
		{
			"ipv6",
			args{net.ParseIP("fe80::1:2:3:4")},
			net.IP([]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeIP(tt.args.ip)
			assert.Equal(t, tt.want, got, "NormalizeIP()")
		})
	}
}

func parseCIDR(t *testing.T, s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	require.Nil(t, err, "net.ParseCIDR(%s) error %v", s, err)
	return n
}

func TestIsIPv6LLMatch(t *testing.T) {
	type args struct {
		expected net.IP
		actual   *net.IPNet
		local    bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"ipv4/nonlocal",
			args{
				net.ParseIP("fe80::1234"),
				parseCIDR(t, "1.2.3.4/32"),
				false,
			},
			false,
		},
		{
			"ipv4/local",
			args{
				net.ParseIP("fe80::1234"),
				parseCIDR(t, "1.2.3.4/32"),
				true,
			},
			false,
		},
		{
			"ipv6/nonlocal mismatch addr",
			args{
				net.ParseIP("fe80::1234"),
				parseCIDR(t, "fe80::1235/128"),
				false,
			},
			false,
		},
		{
			"ipv6/nonlocal mismatch mask",
			args{
				net.ParseIP("fe80::1234"),
				parseCIDR(t, "fe80::1234/64"),
				false,
			},
			false,
		},
		{
			"ipv6/nonlocal match",
			args{
				net.ParseIP("fe80::1234"),
				parseCIDR(t, "fe80::1234/128"),
				false,
			},
			true,
		},
		{
			"ipv6/local mismatch addr",
			args{
				net.ParseIP("fe80:1234::"),
				parseCIDR(t, "fe80:1235::/64"),
				true,
			},
			false,
		},
		{
			"ipv6/local mismatch mask",
			args{
				net.ParseIP("fe80::1234"),
				parseCIDR(t, "fe80::1234/128"),
				true,
			},
			false,
		},
		{
			"ipv6/local match",
			args{
				net.ParseIP("fe80:1234::"),
				parseCIDR(t, "fe80:1234::/64"),
				true,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIPv6LLMatch(tt.args.expected, tt.args.actual, tt.args.local)
			assert.Equal(t, tt.want, got, "IsIPv6LLMatch()")
		})
	}
}

func TestIsGloballyRoutable(t *testing.T) {
	rb := func(l int, prefix ...byte) []byte {
		r := make([]byte, l)
		rand.Read(r)
		copy(r, prefix)
		return r
	}
	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{
			"ipv4: localhost",
			net.IPv4(127, 0, 0, 1),
			false,
		},
		{
			"ipv6: localhost",
			net.IPv6loopback,
			false,
		},
		{
			"ipv4: CG-NAT",
			// 100.64/10
			net.IPv4(100, byte(64+rand.Intn(64)), byte(rand.Intn(256)), byte(rand.Intn(256))),
			false,
		},
		{
			"ipv4: google",
			net.IPv4(8, 8, 8, 8),
			true,
		},
		{
			"ipv6: google",
			net.ParseIP("2001:4860:4860::8888"),
			true,
		},
		{
			// fec0::/10: this is deprecated in ipv6, but still not routeable
			"ipv6: site-local",
			net.IP(rb(16, 0xfe, byte(0xc0+rand.Intn(64)))),
			false,
		},
		{
			// fe80::/7
			"ipv6: link-local",
			net.IP(rb(16, 0xfe, byte(0x80+rand.Intn(64)))),
			false,
		},
		{
			// fc00/7
			"ipv6: ula",
			net.IP(rb(16, byte(0xfc+rand.Intn(2)))),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsGloballyRoutable(tt.ip))
		})
	}
}
