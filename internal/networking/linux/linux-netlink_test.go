package linux

import (
	"testing"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/native"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func containsIface(ifaces []networking.Interface, predicate func(networking.Interface) bool) bool {
	for _, iface := range ifaces {
		if predicate(iface) {
			return true
		}
	}
	return false
}

func Test_linuxEnvironment_Interfaces(t *testing.T) {
	type fields struct {
		create bool

		GoEnvironment native.GoEnvironment
		nlh           *netlink.Handle
	}
	tests := []struct {
		name      string
		fields    fields
		want      []networking.Interface
		wantErr   bool
		wantCheck func(*testing.T, []networking.Interface, error)
	}{
		{
			"can retrieve interfaces",
			fields{create: true},
			nil,
			false,
			func(t *testing.T, ifaces []networking.Interface, err error) {
				for _, iface := range ifaces {
					assert.IsType(t, &linuxInterface{}, iface)
				}
				assert.True(t, containsIface(ifaces, func(iface networking.Interface) bool {
					require.NotNil(t, iface)
					return iface.Name() == "lo"
				}), "Should find a localhost interface")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e *linuxEnvironment
			if tt.fields.create {
				ee, err := CreateLinux()
				require.Nil(t, err)
				defer ee.Close()
				require.IsType(t, &linuxEnvironment{}, ee)
				e = ee.(*linuxEnvironment)
			} else {
				e = &linuxEnvironment{
					GoEnvironment: tt.fields.GoEnvironment,
					nlh:           tt.fields.nlh,
				}
			}
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

func Test_linuxEnvironment_InterfaceByName(t *testing.T) {
	type fields struct {
		create bool

		GoEnvironment native.GoEnvironment
		nlh           *netlink.Handle
	}
	type args struct {
		name string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      networking.Interface
		wantErr   bool
		wantCheck func(*testing.T, networking.Interface, error)
	}{
		{
			"localhost",
			fields{create: true},
			args{"lo"},
			nil,
			false,
			func(t *testing.T, iface networking.Interface, err error) {
				require.IsType(t, &linuxInterface{}, iface)
				assert.Equal(t, "lo", iface.Name())
				assert.True(t, iface.IsUp())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e *linuxEnvironment
			if tt.fields.create {
				ee, err := CreateLinux()
				require.Nil(t, err)
				defer ee.Close()
				require.IsType(t, &linuxEnvironment{}, ee)
				e = ee.(*linuxEnvironment)
			} else {
				e = &linuxEnvironment{
					GoEnvironment: tt.fields.GoEnvironment,
					nlh:           tt.fields.nlh,
				}
			}
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
