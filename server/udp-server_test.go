package server

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/internal/mocks"
	"github.com/fastcat/wirelink/internal/networking"
	netmocks "github.com/fastcat/wirelink/internal/networking/mocks"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/signing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
				signer: signing.New(privateKey),
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
			env := &netmocks.Environment{}
			env.Test(t)
			env.On("Interfaces").Once().Return([]networking.Interface{}, nil)
			got, err := Create(env, ctrl, tt.args.config)
			tt.assertion(t, err)
			if tt.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				// can't check the whole linkserver object
				assert.Equal(t, tt.want.config, got.config)
				assert.Equal(t, env, got.net)
				// assert.Equal(t, tt.want.net, got.net)
				assert.Equal(t, tt.want.conn, got.conn)
				assert.Equal(t, tt.want.addr, got.addr)
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

func TestLifecycle_Empty(t *testing.T) {
	wgIface := fmt.Sprintf("wg%d", rand.Int())
	ethIface := fmt.Sprintf("eth%d", rand.Int())
	port := rand.Intn(65536)
	ethIP4 := testutils.RandIPNet(t, net.IPv4len, []byte{100}, nil, 24)
	wgIP4 := testutils.RandIPNet(t, net.IPv4len, []byte{10}, nil, 24)
	privateKey, publicKey := testutils.MustKeyPair(t)
	localAutoIP := autopeer.AutoAddress(publicKey)

	ctrl := &mocks.WgClient{}
	ctrl.On("Device", wgIface).Return(
		&wgtypes.Device{
			Name:       wgIface,
			PrivateKey: privateKey,
			PublicKey:  publicKey,
			ListenPort: port,
			Peers:      []wgtypes.Peer{},
		},
		nil,
	)
	ctrl.On("Close").Once().Return(nil)

	cfg := &config.Server{
		Iface: wgIface,
	}

	env := &netmocks.Environment{}
	env.Test(t)
	env.On("Interfaces").Once().Return([]networking.Interface{}, nil)
	env.On("Close").Once().Return(nil)

	s, err := Create(env, ctrl, cfg)
	require.NoError(t, err)
	require.NotNil(t, s)

	mockEth := env.WithInterface(ethIface)
	mockEth.WithAddrs(ethIP4)

	mockWg := env.WithInterface(wgIface)
	mockWg.WithAddrs(wgIP4)
	mockWg.On("AddAddr", net.IPNet{
		IP:   localAutoIP,
		Mask: net.CIDRMask(4*net.IPv6len, 8*net.IPv6len),
	}).Once().Return(nil)

	mockUDP := env.RegisterUDPConn(&netmocks.UDPConn{})
	env.On("ListenUDP",
		"udp6",
		&net.UDPAddr{IP: localAutoIP, Port: port + 1, Zone: wgIface},
	).Once().Return(mockUDP, nil)
	mockUDP.On("ReadPackets",
		// naming the context type is hard, they are private impl details
		mock.Anything,
		mock.AnythingOfType("int"),
		mock.AnythingOfType("chan<- *networking.UDPPacket"),
	).Once().Return(func(ctx context.Context, maxSize int, output chan<- *networking.UDPPacket) error {
		// TODO: inject some packets
		close(output)
		return nil
	})
	mockUDP.On("SetWriteDeadline", mock.AnythingOfType("time.Time")).Return(nil)
	mockUDP.On("Close").Once().Return(nil)

	env.WithKnownInterfaces()
	env.Test(t)
	s.net = env

	err = s.Start()
	require.NoError(t, err)

	assert.Regexp(t,
		fmt.Sprintf("^Version [^ ]+ on \\{%s\\} \\[%s\\]:%d \\(leaf, quiet\\)$", wgIface, localAutoIP, port+1),
		s.Describe(),
	)
	assert.Equal(t, localAutoIP, s.Address())
	assert.Equal(t, port+1, s.Port())

	s.Stop()
	err = s.Wait()
	assert.NoError(t, err)
	// TODO: asserts

	s.Close()

	// this will propagate to all the other virtual network objects
	env.AssertExpectations(t)
	ctrl.AssertExpectations(t)
}
