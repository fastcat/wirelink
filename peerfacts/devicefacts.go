package peerfacts

import (
	"fmt"
	"net"
	"time"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DeviceFacts returns facts about the local wireguard device
func DeviceFacts(dev *wgtypes.Device, ttl time.Duration) (ret []fact.Fact, err error) {
	if dev == nil {
		return nil, fmt.Errorf("No device")
	}
	if ttl.Seconds() < 0 || ttl.Seconds() > 255 {
		return nil, fmt.Errorf("ttl out of range")
	}

	expiration := time.Now().Add(ttl)

	addAttr := func(attr fact.Attribute, value fact.Value) {
		fact := fact.Fact{
			Attribute: attr,
			Subject:   PeerSubject{dev.PublicKey},
			Value:     value,
			Expires:   expiration,
		}
		ret = append(ret, fact)
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
				addAttr(fact.AttributeEndpointV4, IPPortValue{ip4, dev.ListenPort})
			} else {
				addAttr(fact.AttributeEndpointV6, IPPortValue{ipn.IP, dev.ListenPort})
			}
		}
	}

	autoAddress := autopeer.AutoAddress(dev.PublicKey)
	if autoAddress != nil {
		addAttr(fact.AttributeAllowedCidrV6, IPNetValue{net.IPNet{
			IP:   autoAddress,
			Mask: net.CIDRMask(128, 128),
		}})
	}

	// TODO: more

	return ret, nil
}
