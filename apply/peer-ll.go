package apply

import (
	"bytes"
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsurePeerAutoIP updates the config of the device, if needed, to ensure all
// peers have their IPV6-LL IP listed in their AllowedIPs.
// It returns the number of peers modified and any error that happens
func EnsurePeerAutoIP(ctrl *wgctrl.Client, dev *wgtypes.Device) (int, error) {
	var cfg wgtypes.Config
PEERS:
	for _, peer := range dev.Peers {
		autoaddr := autopeer.AutoAddress(peer.PublicKey)
		for _, aip := range peer.AllowedIPs {
			ones, bits := aip.Mask.Size()
			if ones == 8*net.IPv6len && bits == 8*net.IPv6len && bytes.Equal(autoaddr, aip.IP) {
				continue PEERS
			}
		}
		// didn't find it
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
			AllowedIPs: []net.IPNet{net.IPNet{
				IP:   autoaddr,
				Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
			}},
		})
	}

	err := ctrl.ConfigureDevice(dev.Name, cfg)
	if err != nil {
		return 0, errors.Wrapf(err,
			"Unable to configure %s with %d new peer IPv6-LL AllowedIPs", dev.Name, len(cfg.Peers))
	}

	return len(cfg.Peers), nil
}
