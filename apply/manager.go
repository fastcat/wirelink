package apply

import (
	"github.com/pkg/errors"

	"github.com/vishvananda/netlink"
)

// Manager is a wrapper for applying local configuration changes
type Manager struct {
	nlh *netlink.Handle
}

// NewManager instantiates a new Manager object with its own netlink handle
func NewManager() (*Manager, error) {
	var ret Manager
	nlh, err := netlink.NewHandle()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to make a new netlink handle")
	}
	ret.nlh = nlh

	return &ret, nil
}

// Close releases resources associated with the manager
func (m *Manager) Close() {
	m.nlh.Delete()
	m.nlh = nil
}
