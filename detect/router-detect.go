// Package detect provides utilities to detect if the local system is a router,
// or if some remote peer is one.
package detect

import (
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// IsPeerRouter considers a router to be a peer that has a global unicast allowed
// IP with a CIDR mask less than the full IP
func IsPeerRouter(peer *wgtypes.Peer) bool {
	for _, aip := range peer.AllowedIPs {
		// don't ignore private (RFC1918-ish) subnets here, as they are a valid
		// thing to be a router for
		if !aip.IP.IsGlobalUnicast() {
			continue
		}
		apiNorm := util.NormalizeIP(aip.IP)
		ones, size := aip.Mask.Size()
		if len(apiNorm)*8 == size && ones < size {
			return true
		}
	}
	return false
}

// IsDeviceRouter tries to detect whether the local device is a router for other peers.
// Currently it does this by assuming that it is a router if and only if nobody else is.
// TODO: try to check local networking config for signs of routing configuration
func IsDeviceRouter(dev *wgtypes.Device) bool {
	otherRouters := false
	for _, p := range dev.Peers {
		if IsPeerRouter(&p) {
			log.Debug("Router autodetect: found router peer %v", p.PublicKey)
			otherRouters = true
			break
		}
	}

	return !otherRouters
}
