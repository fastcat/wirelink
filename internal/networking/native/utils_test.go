package native

import (
	"net"
	"testing"

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
