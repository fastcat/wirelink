package native

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustNetInterface(t *testing.T) func(iface *net.Interface, err error) *net.Interface {
	return func(iface *net.Interface, err error) *net.Interface {
		require.Nil(t, err)
		require.NotNil(t, iface)
		return iface
	}
}
