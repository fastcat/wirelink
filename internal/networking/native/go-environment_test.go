package native

import (
	"fmt"
	"math/rand"
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func containsIface(ifaces []*GoInterface, predicate func(*GoInterface) bool) bool {
	for _, iface := range ifaces {
		if predicate(iface) {
			return true
		}
	}
	return false
}

func mustNetInterface(t *testing.T) func(iface *net.Interface, err error) *net.Interface {
	return func(iface *net.Interface, err error) *net.Interface {
		require.Nil(t, err)
		require.NotNil(t, iface)
		return iface
	}
}

func TestGoEnvironment_Interfaces(t *testing.T) {
	tests := []struct {
		name      string
		e         *GoEnvironment
		want      []*GoInterface
		wantErr   bool
		wantCheck func(*testing.T, []*GoInterface, error)
	}{
		{
			"can retrieve interfaces",
			&GoEnvironment{},
			nil,
			false,
			func(t *testing.T, ifaces []*GoInterface, err error) {
				assert.True(t, containsIface(ifaces, func(iface *GoInterface) bool {
					require.NotNil(t, iface)
					return iface.Name() == "lo"
				}), "Should find a localhost interface")
				assert.GreaterOrEqual(t, len(ifaces), 2)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &GoEnvironment{}
			got, err := e.Interfaces()
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}
			if tt.wantCheck != nil {
				tt.wantCheck(t, got, err)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestGoEnvironment_InterfaceByName(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name      string
		e         *GoEnvironment
		args      args
		want      *GoInterface
		wantErr   bool
		wantCheck func(*testing.T, *GoInterface, error)
	}{
		{
			"reasonable localhost results",
			&GoEnvironment{},
			args{"lo"},
			nil,
			false,
			func(t *testing.T, iface *GoInterface, err error) {
				require.NotNil(t, iface)
				assert.Equal(t, iface.Name(), "lo")
				assert.True(t, iface.IsUp())
			},
		},
		{
			"not found error",
			&GoEnvironment{},
			args{fmt.Sprintf("xyzzy%d", rand.Int63())},
			nil,
			true,
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &GoEnvironment{}
			got, err := e.InterfaceByName(tt.args.name)
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}
			if tt.wantCheck != nil {
				tt.wantCheck(t, got, err)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestGoInterface_Addrs(t *testing.T) {
	type fields struct {
		Interface net.Interface
	}
	tests := []struct {
		name      string
		fields    fields
		want      []net.IPNet
		wantErr   bool
		wantCheck func(*testing.T, []net.IPNet, error)
	}{
		{
			"localhost",
			fields{*mustNetInterface(t)(net.InterfaceByName("lo"))},
			nil,
			false,
			func(t *testing.T, addrs []net.IPNet, err error) {
				assert.True(t, testutils.ContainsIPNet(addrs, func(addr net.IPNet) bool {
					ones, bits := addr.Mask.Size()
					// check for 127.0.0.1/8
					return net.IPv4(127, 0, 0, 1).Equal(addr.IP) && ones == 8 && bits == 32
				}))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &GoInterface{
				Interface: tt.fields.Interface,
			}
			got, err := i.Addrs()
			if tt.wantErr {
				require.NotNil(t, err)
			} else {
				require.Nil(t, err)
			}
			if tt.wantCheck != nil {
				tt.wantCheck(t, got, err)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
