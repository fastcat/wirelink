package apply

import (
	"net"

	"github.com/pkg/errors"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/util"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsureLocalAutoIP makes sure that the automatic IPv6 link-local IP is
// present on the interface that matches the device
// It returns whether it had to add it, and if any errors happened
func (m *Manager) EnsureLocalAutoIP(dev *wgtypes.Device) (bool, error) {
	link, err := m.nlh.LinkByName(dev.Name)
	if err != nil {
		return false, errors.Wrapf(err, "Unable to get link info for %s", dev.Name)
	}
	addrs, err := m.nlh.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return false, errors.Wrapf(err, "Unable to get IPv6 addresses for %s", dev.Name)
	}

	autoaddr := autopeer.AutoAddress(dev.PublicKey)
	for _, addr := range addrs {
		if util.IsIPv6LLMatch(autoaddr, addr.IPNet, true) {
			return false, nil
		}
	}

	err = m.nlh.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   autoaddr,
			Mask: net.CIDRMask(4*net.IPv6len, 8*net.IPv6len),
		},
	})
	if err != nil {
		return false, errors.Wrapf(err, "Unable to add %v to %s", autoaddr, dev.Name)
	}

	return true, nil
}
