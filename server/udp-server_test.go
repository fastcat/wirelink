package server

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/signing"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreate(t *testing.T) {
	wgIface := fmt.Sprintf("wg%d", rand.Int())
	p := rand.Intn(65536)
	privateKey, publicKey := testutils.MustKeyPair(t)

	type args struct {
		ctrl   func(*testing.T) *mocks.WgClient
		config *config.Server
	}
	tests := []struct {
		name      string
		args      args
		want      *LinkServer
		assertion require.ErrorAssertionFunc
	}{
		{
			"basic",
			args{
				func(t *testing.T) *mocks.WgClient {
					ret := &mocks.WgClient{}
					ret.On("Device", wgIface).Return(
						&wgtypes.Device{
							Name:       wgIface,
							ListenPort: p,
							PrivateKey: privateKey,
							PublicKey:  publicKey,
						},
						nil,
					)
					return ret
				},
				&config.Server{
					Iface: wgIface,
				},
			},
			&LinkServer{
				config: &config.Server{
					Iface: wgIface,
					Port:  p + 1,
				},
				addr: net.UDPAddr{
					IP:   autopeer.AutoAddress(publicKey),
					Port: p + 1,
					Zone: wgIface,
				},
				signer: signing.New(&privateKey),
			},
			require.NoError,
		},
		// TODO: pre-selected port
		// TODO: error paths
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := tt.args.ctrl(t)
			ctrl.Test(t)
			got, err := Create(ctrl, tt.args.config)
			tt.assertion(t, err)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				// can't check the whole linkserver object
				assert.Equal(t, tt.want.config, got.config)
				assert.Equal(t, tt.want.net, got.net)
				assert.Equal(t, tt.want.conn, got.conn)
				assert.Equal(t, tt.want.addr, got.addr)
				assert.NotNil(t, got.stateAccess)
				assert.NotNil(t, got.eg)
				assert.NotNil(t, got.ctx)
				assert.NotNil(t, got.cancel)
				assert.NotNil(t, got.peerKnowledge)
				assert.NotNil(t, got.peerConfig)
				assert.Equal(t, tt.want.signer, got.signer)
				assert.NotNil(t, got.printRequested)
			}
			ctrl.AssertExpectations(t)
		})
	}
}
