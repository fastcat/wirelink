package device

import (
	"fmt"

	"github.com/fastcat/wirelink/apply"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsurePeersAutoIP updates the config of the device, if needed, to ensure all
// peers have their IPv6-LL IP listed in their AllowedIPs.
// It returns the number of peers modified and any error that happens
func (d *Device) EnsurePeersAutoIP() (int, error) {
	state, err := d.State()
	if err != nil {
		return 0, err
	}

	var cfg wgtypes.Config
	for _, peer := range state.Peers {
		pcfg, _ := apply.EnsurePeerAutoIP(&peer, nil)
		if pcfg != nil {
			cfg.Peers = append(cfg.Peers, *pcfg)
		}
	}

	if len(cfg.Peers) == 0 {
		return 0, nil
	}

	err = d.ConfigureDevice(cfg)
	if err != nil {
		return 0, fmt.Errorf(
			"unable to configure %s with %d new peer IPv6-LL AllowedIPs: %w", d.iface, len(cfg.Peers), err)
	}

	return len(cfg.Peers), nil
}
