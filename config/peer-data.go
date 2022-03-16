package config

import (
	"fmt"
	"net"

	"github.com/fastcat/wirelink/trust"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerData represents the raw data to configure a peer read from the config file
type PeerData struct {
	PublicKey     string
	Name          string
	Trust         string
	FactExchanger bool
	Endpoints     []string
	AllowedIPs    []string
	Basic         bool
}

// Parse validates the info in the PeerData and returns the parsed tuple + error
func (p *PeerData) Parse() (key wgtypes.Key, peer Peer, err error) {
	if key, err = wgtypes.ParseKey(p.PublicKey); err != nil {
		return
	}
	peer.Name = p.Name
	if p.Trust != "" {
		val, ok := trust.Values[p.Trust]
		if !ok {
			err = fmt.Errorf("invalid trust level '%s'", p.Trust)
			return
		}
		peer.Trust = &val
	}
	peer.FactExchanger = p.FactExchanger
	peer.Endpoints = make([]PeerEndpoint, 0, len(p.Endpoints))
	// we don't do the DNS resolution here because we want it to refresh
	// periodically, esp. if we move across a split horizon boundary
	// we do want to validate the host/port split however
	for _, ep := range p.Endpoints {
		var host, portString string
		var port int
		if host, portString, err = net.SplitHostPort(ep); err != nil {
			err = fmt.Errorf("bad endpoint '%s' for '%s'='%s': %w", ep, p.PublicKey, p.Name, err)
			return
		}
		if port, err = net.LookupPort("udp", portString); err != nil {
			err = fmt.Errorf("bad endpoint port in '%s' for '%s'='%s': %w", ep, p.PublicKey, p.Name, err)
			return
		}

		// try to resolve the host, ignoring DNS errors and just looking for parse errors
		// NOTE: it's actually really hard to get anything other than a DNSError out of LookupIP
		// anything that doesn't parse as an IP is more or less assumed to be a hostname,
		// even if it is not actually valid as such (e.g. all numbers), and then a lookup attempted,
		// and if the lookup fails, we get an DNS error
		_, err = net.LookupIP(host)
		if _, ok := err.(*net.DNSError); ok {
			// ignore DNS errors ... which actually ends up as basically everything except for a
			// parse error for giving the empty string
			err = nil
		} else if err != nil {
			// this branch is very hard, if not impossible, to reach in a test or in the real world
			err = fmt.Errorf("bad endpoint host in '%s' for '%s'='%s': %w", ep, p.PublicKey, p.Name, err)
			return
		}

		// TODO: can validate host portion is syntactically valid: do a lookup and
		// ignore host not found errors

		peer.Endpoints = append(peer.Endpoints, PeerEndpoint{
			Host: host,
			Port: port,
		})
	}

	peer.AllowedIPs = make([]net.IPNet, 0, len(p.AllowedIPs))
	for _, aip := range p.AllowedIPs {
		var ipn *net.IPNet
		_, ipn, err = net.ParseCIDR(aip)
		if err != nil {
			err = fmt.Errorf("bad AllowedIP '%s' for '%s'='%s': %w", aip, p.PublicKey, p.Name, err)
			return
		}
		// NOTE: we don't need to run ipn.IP through ipn.Mask, as ParseCIDR does that for us
		// we want to do that so config can contain minor harmless mistakes, or also use the
		// masked-out bits as documentation for the peer's own/primary IP within that network
		// ipn is returned by reference, should never be returned nil
		peer.AllowedIPs = append(peer.AllowedIPs, *ipn)
	}

	peer.Basic = p.Basic

	return
}
