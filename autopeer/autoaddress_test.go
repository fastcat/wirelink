package autopeer

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestAutoAddressNet(t *testing.T) {
	type args struct {
		key wgtypes.Key
	}
	ka := func(ks string) args {
		k, err := wgtypes.ParseKey(ks)
		require.Nil(t, err)
		return args{k}
	}
	np := func(ip string) net.IPNet {
		_, n, err := net.ParseCIDR(ip)
		require.Nil(t, err)
		return *n
	}
	tests := []struct {
		name string
		args args
		want net.IPNet
	}{
		{"1", ka("6X/iz1GyW9euj9JIdP7PUl14eoWyoQiAa+BDTB38GhE="), np("fe80::afec:ee83:716b:51ac/128")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AutoAddressNet(tt.args.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Benchmark_autoAddress(b *testing.B) {
	k, err := wgtypes.GeneratePrivateKey()
	require.NoError(b, err)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		autoAddress(k)
	}
}

func BenchmarkAutoAddress(b *testing.B) {
	k, err := wgtypes.GeneratePrivateKey()
	require.NoError(b, err)
	// seed the cache
	AutoAddress(k)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		AutoAddress(k)
	}
}
