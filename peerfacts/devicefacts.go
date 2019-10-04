package peerfacts

import (
	"fmt"
	"net"
	"time"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/fact/types"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DeviceFacts returns facts about the local wireguard device
func DeviceFacts(dev *wgtypes.Device, ttl time.Duration) (ret []*fact.Fact, err error) {
	if ttl.Seconds() < 0 || ttl.Seconds() > 255 {
		return nil, fmt.Errorf("ttl out of range")
	}

	expiration := time.Now().Add(ttl)

	addAttr := func(attr types.Attribute, value types.Value) {
		ret = append(ret, &fact.Fact{
			Attribute: attr,
			Subject:   types.PeerSubject{Key: dev.PublicKey},
			Value:     value,
			Expires:   expiration,
		})
	}

	// map listen port to each local ip address, except link-local ones
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		// ignore interfaces that aren't up
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			// on linux at least this should always be a safe type assertion
			ipn := addr.(*net.IPNet)
			if ipn == nil || !ipn.IP.IsGlobalUnicast() {
				// ignore localhost for sure, and link local addresses at least for now
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil {
				addAttr(fact.AttributeEndpointV4, types.IPPortValue{IP: ip4, Port: dev.ListenPort})
			} else {
				addAttr(fact.AttributeEndpointV6, types.IPPortValue{IP: ipn.IP, Port: dev.ListenPort})
			}
		}
	}

	// don't publish the autoaddress, everyone can figure that out on their own,
	// and must already know it in order to receive the data anyways

	// TODO: more?

	return ret, nil
}
