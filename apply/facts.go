package apply

import (
	"net"

	"github.com/fastcat/wirelink/fact"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// EnsureAllowedIPs updates the device config if needed to add all the
// AllowedIPs from the facts to the peer
func EnsureAllowedIPs(ctrl *wgctrl.Client, deviceName string, peer *wgtypes.Peer, facts []*fact.Fact) (added int, err error) {
	curAIPs := make(map[string]bool)
	for _, aip := range peer.AllowedIPs {
		ipn := fact.IPNetValue{IPNet: aip}
		curAIPs[string(ipn.Bytes())] = true
	}

	var toAdd []net.IPNet

	for _, f := range facts {
		switch f.Attribute {
		case fact.AttributeAllowedCidrV4:
			fallthrough
		case fact.AttributeAllowedCidrV6:
			if curAIPs[string(f.Value.Bytes())] {
				continue
			}
			if ipn, ok := f.Value.(*fact.IPNetValue); ok {
				toAdd = append(toAdd, ipn.IPNet)
			}
		}
	}

	if len(toAdd) == 0 {
		return
	}

	err = ctrl.ConfigureDevice(deviceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			wgtypes.PeerConfig{
				PublicKey:  peer.PublicKey,
				AllowedIPs: toAdd,
			},
		},
	})

	return len(toAdd), err
}
