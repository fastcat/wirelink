package apply

import (
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/util"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsurePeerAutoIP updates the config of the device, if needed, to ensure all
// peers have their IPv6-LL IP listed in their AllowedIPs.
// It returns the number of peers modified and any error that happens
func EnsurePeerAutoIP(ctrl *wgctrl.Client, dev *wgtypes.Device) (int, error) {
	var cfg wgtypes.Config
PEERS:
	for _, peer := range dev.Peers {
		autoaddr := autopeer.AutoAddress(peer.PublicKey)
		for _, aip := range peer.AllowedIPs {
			if util.IsIPv6LLMatch(autoaddr, &aip, false) {
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

// OnlyAutoIP configures a peer to have _only_ its IPv6-LL IP in its AllowedIPs
// it returns any error that happens
func OnlyAutoIP(ctrl *wgctrl.Client, deviceName string, peer *wgtypes.Peer) error {
	autoaddr := autopeer.AutoAddress(peer.PublicKey)
	if len(peer.AllowedIPs) == 1 && peer.AllowedIPs[0].IP.Equal(autoaddr) {
		ones, bits := peer.AllowedIPs[0].Mask.Size()
		if ones == 8*net.IPv6len && bits == 8*net.IPv6len {
			// no change required
			return nil
		}
	}
	var cfg wgtypes.Config
	cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
		PublicKey:         peer.PublicKey,
		ReplaceAllowedIPs: true,
		AllowedIPs: []net.IPNet{net.IPNet{
			IP:   autoaddr,
			Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
		}},
	})
	err := ctrl.ConfigureDevice(deviceName, cfg)
	if err != nil {
		return errors.Wrapf(err, "Unable to configure %s to restrict peer %s to IPv6-LL only",
			deviceName, peer.PublicKey)
	}
	return nil
}
