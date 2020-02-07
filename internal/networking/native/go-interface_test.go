package native

import (
	"net"
	"testing"

	"github.com/fastcat/wirelink/internal/testutils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
