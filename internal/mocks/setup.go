package mocks

import "testing"

// SetupClient creates a new mock, calls the setup function on it, and returns it
func SetupClient(t *testing.T, setup func(m *WgClient)) *WgClient {
	m := &WgClient{}
	m.Test(t)
	if setup != nil {
		setup(m)
	}
	return m
}
