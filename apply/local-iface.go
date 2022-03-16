package apply

import (
	"fmt"
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsureLocalAutoIP makes sure that the automatic IPv6 link-local IP is
// present on the interface that matches the device
// It returns whether it had to add it, and if any errors happened
func EnsureLocalAutoIP(env networking.Environment, dev *wgtypes.Device) (bool, error) {
	iface, err := env.InterfaceByName(dev.Name)
	if err != nil {
		return false, fmt.Errorf("unable to get interface info for %s: %w", dev.Name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("unable to get addresses for %s: %w", dev.Name, err)
	}

	autoaddr := autopeer.AutoAddress(dev.PublicKey)
	for _, addr := range addrs {
		if util.IsIPv6LLMatch(autoaddr, &addr, true) {
			return false, nil
		}
	}

	err = iface.AddAddr(net.IPNet{
		IP:   autoaddr,
		Mask: net.CIDRMask(4*net.IPv6len, 8*net.IPv6len),
	})
	if err != nil {
		return false, fmt.Errorf("unable to add %v to %s: %w", autoaddr, dev.Name, err)
	}

	log.Debug("Added local IPv6-LL %v to %s", autoaddr, dev.Name)

	return true, nil
}
