package peerfacts

import (
	"fmt"
	"net"
	"time"

	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// DeviceFacts returns facts about the local wireguard device and the peer that
// it represents, but not about other peers configured in the device.
func DeviceFacts(
	dev *wgtypes.Device,
	now time.Time,
	ttl time.Duration,
	config *config.Server,
	env networking.Environment,
) (
	ret []*fact.Fact,
	err error,
) {
	if ttl.Seconds() < 0 || ttl.Seconds() > 255 {
		return nil, fmt.Errorf("ttl out of range")
	}

	expiration := now.Add(ttl)

	addAttr := func(attr fact.Attribute, value fact.Value) {
		ret = append(ret, &fact.Fact{
			Attribute: attr,
			Subject:   &fact.PeerSubject{Key: dev.PublicKey},
			Value:     value,
			Expires:   expiration,
		})
	}

	// map listen port to each local ip address, except link-local ones
	ifaces, err := env.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		// ignore interfaces that aren't up
		if !iface.IsUp() {
			continue
		}
		// different reporting rules for the wireguard interface
		if iface.Name() == dev.Name {
			// but maybe do report allowedIPs, if we don't have them explicitly configured
			if config.IsRouterNow && len(config.Peers.AllowedIPs(dev.PublicKey)) == 0 {
				log.Debug("Reporting AllowedIPs for local iface %s", iface.Name())
				err = forEachAddr(iface, func(ipn net.IPNet) error {
					log.Debug("Reporting local AllowedIP: %s: %v", iface.Name(), ipn)
					// apply the mask to the IP so it matches how it will be interpreted by WG later
					normalized := net.IPNet{
						IP:   ipn.IP.Mask(ipn.Mask),
						Mask: ipn.Mask,
					}
					// this should never happen
					if normalized.IP == nil {
						return fmt.Errorf("what? Local interface ip/mask are mismatched sizes? %v", ipn)
					}
					if ip4 := ipn.IP.To4(); ip4 != nil {
						addAttr(fact.AttributeAllowedCidrV4, &fact.IPNetValue{IPNet: normalized})
					} else {
						addAttr(fact.AttributeAllowedCidrV6, &fact.IPNetValue{IPNet: normalized})
					}
					return nil
				})
				if err != nil {
					return nil, err
				}
			}
			continue
		}

		if !config.ShouldReportIface(iface.Name()) {
			log.Debug("Excluding local iface '%s'\n", iface.Name())
			continue
		}
		err := forEachAddr(iface, func(ipn net.IPNet) error {
			log.Debug("Reporting local endpoint: %s: %v:%v", iface.Name(), ipn.IP, dev.ListenPort)
			if ip4 := ipn.IP.To4(); ip4 != nil {
				addAttr(fact.AttributeEndpointV4, &fact.IPPortValue{IP: ip4, Port: dev.ListenPort})
			} else {
				addAttr(fact.AttributeEndpointV6, &fact.IPPortValue{IP: ipn.IP, Port: dev.ListenPort})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// don't publish the autoaddress, everyone can figure that out on their own,
	// and must already know it in order to receive the data anyways

	// TODO: more?

	return ret, nil
}

func forEachAddr(iface networking.Interface, handler func(ipn net.IPNet) error) error {
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if !addr.IP.IsGlobalUnicast() {
			// ignore localhost for sure, and link local addresses at least for now,
			// but not private (RFC1918) addresses, as they are valid as endpoints and
			// allowed IP subnets.
			continue
		}
		err = handler(addr)
		if err != nil {
			return err
		}
	}
	return nil
}
