package apply

import (
	"net"

	"github.com/fastcat/wirelink/autopeer"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
func EnsurePeerAutoIP(peer *wgtypes.Peer, cfg *wgtypes.PeerConfig) (peerConfig *wgtypes.PeerConfig, added bool) {
	autoaddr := autopeer.AutoAddress(peer.PublicKey)
	hasNow := hasAutoIP(autoaddr, peer.AllowedIPs)
	var alreadyAdding bool
	var rebuilding bool
	if cfg != nil {
		alreadyAdding = hasAutoIP(autoaddr, cfg.AllowedIPs)
		rebuilding = cfg.ReplaceAllowedIPs
	}
	// we can skip this if we're already adding it, or if we have it and aren't rebuilding
	if alreadyAdding || hasNow && !rebuilding {
		return cfg, false
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
	// don't "say" we added it (for logging purposes) if we are "re-adding" it
	// as part of a rebuild
	return cfg, !hasNow
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
	cfg.AllowedIPs = []net.IPNet{{
		IP:   autoaddr,
		Mask: net.CIDRMask(8*net.IPv6len, 8*net.IPv6len),
	}}

	return cfg
}
