package util

import (
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
