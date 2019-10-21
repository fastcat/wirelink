package apply

import (
	"net"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsurePeersAutoIP updates the config of the device, if needed, to ensure all
// peers have their IPv6-LL IP listed in their AllowedIPs.
// It returns the number of peers modified and any error that happens
func EnsurePeersAutoIP(ctrl *wgctrl.Client, dev *wgtypes.Device) (int, error) {
	var cfg wgtypes.Config
	for _, peer := range dev.Peers {
		pcfg := EnsurePeerAutoIP(&peer, nil)
		if pcfg != nil {
			cfg.Peers = append(cfg.Peers, *pcfg)
		}
	}

	if len(cfg.Peers) == 0 {
		return 0, nil
	}

	err := ctrl.ConfigureDevice(dev.Name, cfg)
	if err != nil {
		return 0, errors.Wrapf(err,
			"Unable to configure %s with %d new peer IPv6-LL AllowedIPs", dev.Name, len(cfg.Peers))
	}

	return len(cfg.Peers), nil
}

func hasAutoIP(autoaddr net.IP, aips []net.IPNet) bool {
	for _, aip := range aips {
		if aip.IP.Equal(autoaddr) {
			ones, bits := aip.Mask.Size()
			if ones == 8*net.IPv6len && bits == 8*net.IPv6len {
				return true
			}
		}
	}
	return false
}

// EnsurePeerAutoIP ensures that the config (if any) for the given peer key includes
// its automatic IPv6-LL address.
func EnsurePeerAutoIP(peer *wgtypes.Peer, cfg *wgtypes.PeerConfig) *wgtypes.PeerConfig {
	autoaddr := autopeer.AutoAddress(peer.PublicKey)
	skip := hasAutoIP(autoaddr, peer.AllowedIPs)
	if cfg != nil && !skip {
		skip = hasAutoIP(autoaddr, cfg.AllowedIPs)
	}
	if skip {
		return cfg
	}

	if cfg == nil {
		cfg = &wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
		}
	}

	cfg.AllowedIPs = append(cfg.AllowedIPs, net.IPNet{
		IP:   autoaddr,
		Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
	})
	return cfg
}

// OnlyAutoIP configures a peer to have _only_ its IPv6-LL IP in its AllowedIPs
// it returns whether a change was attempted and any error that happens
func OnlyAutoIP(peer *wgtypes.Peer, cfg *wgtypes.PeerConfig) *wgtypes.PeerConfig {
	autoaddr := autopeer.AutoAddress(peer.PublicKey)
	// don't bother checking for not needing a change, just always set it up
	if cfg != nil && cfg.ReplaceAllowedIPs && len(cfg.AllowedIPs) == 1 && hasAutoIP(autoaddr, cfg.AllowedIPs) {
		// already set to apply this config
		return cfg
	}
	if len(peer.AllowedIPs) == 1 && hasAutoIP(autoaddr, peer.AllowedIPs) {
		// if peer is already configured properly and config isn't going to change it, do nothing
		if cfg == nil {
			return cfg
		}
		if len(cfg.AllowedIPs) == 0 && !cfg.ReplaceAllowedIPs {
			return cfg
		}
	}

	// peer either isn't setup right, or config is set to change it to something else
	if cfg == nil {
		cfg = &wgtypes.PeerConfig{PublicKey: peer.PublicKey}
	}
	cfg.ReplaceAllowedIPs = true
	cfg.AllowedIPs = []net.IPNet{net.IPNet{
		IP:   autoaddr,
		Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
	}}

	return cfg
}
