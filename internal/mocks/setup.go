package mocks

// SetupClient creates a new mock, calls the setup function on it, and returns it
func SetupClient(setup func(m *WgClient)) *WgClient {
	m := &WgClient{}
	if setup != nil {
		setup(m)
	}
	return m
}
