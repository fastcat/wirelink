package native

import (
	"fmt"
	"math/rand"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestGoEnvironment_NewWgClient(t *testing.T) {
	e := &GoEnvironment{}
	got, err := e.NewWgClient()
	require.NoError(t, err)
	if assert.NotNil(t, got) {
		defer got.Close()
	}
	assert.IsType(t, &wgctrl.Client{}, got)
}
