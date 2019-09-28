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

	// TODO: local ip addresses

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
