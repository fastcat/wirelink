package apply

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/internal/networking/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestEnsureLocalAutoIP(t *testing.T) {
	in1 := fmt.Sprintf("wg%d", rand.Int31())
	k1 := testutils.MustKey(t)

	type args struct {
		env *mocks.Environment
		dev *wgtypes.Device
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			"already configured",
			args{
				env: func() *mocks.Environment {
					ret := &mocks.Environment{}
					ret.WithSimpleInterfaces(map[string]net.IPNet{
						in1: net.IPNet{
							IP:   autopeer.AutoAddress(k1),
							Mask: net.CIDRMask(64, 128),
						},
					})
					return ret
				}(),
				dev: &wgtypes.Device{
					Name:      in1,
					PublicKey: k1,
				},
			},
			false,
			false,
		},
		{
			"do configure",
			args{
				env: func() *mocks.Environment {
					ret := &mocks.Environment{}
					ii := ret.WithSimpleInterfaces(map[string]net.IPNet{
						in1: testutils.RandIPNet(t, net.IPv4len, nil, nil, 24),
					})
					ii[in1].On("AddAddr", net.IPNet{
						IP:   autopeer.AutoAddress(k1),
						Mask: net.CIDRMask(64, 128),
					}).Return(nil)
					return ret
				}(),
				dev: &wgtypes.Device{
					Name:      in1,
					PublicKey: k1,
				},
			},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.env.Test(t)
			got, err := EnsureLocalAutoIP(tt.args.env, tt.args.dev)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}
			assert.Equal(t, tt.want, got)
			tt.args.env.AssertExpectations(t)
		})
	}
}
