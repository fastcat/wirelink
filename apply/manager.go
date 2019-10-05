package apply

import (
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

type Manager struct {
	nlh *netlink.Handle
}

// Create a new Manager
func NewManager() (*Manager, error) {
	var ret Manager
	nlh, err := netlink.NewHandle()
	if err != nil {
		return nil, errors.Wrap(err, "Unable to make a new netlink handle")
	}
	ret.nlh = nlh

	return &ret, nil
}
