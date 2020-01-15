package server

import (
	"net"
	"path/filepath"
	"time"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/peerfacts"
	"github.com/fastcat/wirelink/trust"
	"github.com/fastcat/wirelink/util"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// deviceState does a mutex-protected access to read the current state of the
// wireguard device
func (s *LinkServer) deviceState() (dev *wgtypes.Device, err error) {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	return s.ctrl.Device(s.config.Iface)
}

func (s *LinkServer) shouldReportIface(name string) bool {
	// MUST NOT match any excludes
	for _, glob := range s.config.HideIfaces {
		if matched, err := filepath.Match(glob, name); matched && err == nil {
			log.Debug("Hiding iface '%s' because it matches exclude '%s'\n", name, glob)
			return false
		}
	}
	if len(s.config.ReportIfaces) == 0 {
		log.Debug("Including iface '%s' because no includes are configured", name)
		return true
	}
	// if any includes are specified, name MUST match one of them
	for _, glob := range s.config.ReportIfaces {
		if matched, err := filepath.Match(glob, name); matched && err == nil {
			log.Debug("Including iface '%s' because it matches include '%s'\n", name, glob)
			return true
		}
	}
	log.Debug("Hiding iface '%s' because it doesn't match any includes\n", name)
	return false
}

func (s *LinkServer) collectFacts(dev *wgtypes.Device) (ret []*fact.Fact, err error) {
	log.Debug("Collecting facts...")

	// facts about the local node
	ret, err = peerfacts.DeviceFacts(dev, FactTTL, s.shouldReportIface)
	if err != nil {
		return
	}

	// facts the local node knows about peers configured in the wireguard device
	//FIXME: find a better way to figure out if we should trust our local AIP list
	useLocalAIPs := s.config.IsRouter || s.config.Peers.Trust(dev.PublicKey, trust.Untrusted) >= trust.AddPeer
	for _, peer := range dev.Peers {
		var pf []*fact.Fact
		pf, err = peerfacts.LocalFacts(&peer, FactTTL, useLocalAIPs)
		if err != nil {
			return
		}
		ret = append(ret, pf...)
	}

	expires := time.Now().Add(FactTTL)

	// static facts from the config
	// these may duplicate other known facts, higher layers will dedupe
	for pk, pc := range s.config.Peers {
		// only do static lookups for dead peers
		if pcs, ok := s.peerConfig.Get(pk); ok && (pcs.IsAlive() || pcs.IsHealthy()) {
			log.Debug("Skipping static lookup for OK peer %s", s.peerName(pk))
			continue
		}
		for _, ep := range pc.Endpoints {
			var h, p string
			h, p, err = net.SplitHostPort(ep)
			if err != nil {
				log.Error("Bad endpoint should have been caught at startup: %s", err)
				continue
			}
			var ips []net.IP
			ips, err = net.LookupIP(h)
			if err != nil {
				// DNS lookup errors are generally transient and not worth logging
				continue
			}
			if len(ips) == 0 {
				continue
			}
			var port int
			port, err = net.LookupPort("udp", p)
			if err != nil {
				continue
			}

			for _, ip := range ips {
				// don't publish localhost-ish or link-local addresses,
				// these are not going to be useful, but may appear if we ourselves
				// are listed with a static endpoint that resolves oddly locally
				if !ip.IsGlobalUnicast() {
					continue
				}
				nip := util.NormalizeIP(ip)
				var attr fact.Attribute
				if len(nip) == net.IPv4len {
					attr = fact.AttributeEndpointV4
				} else if len(nip) == net.IPv6len {
					attr = fact.AttributeEndpointV6
				} else {
					continue
				}
				staticFact := &fact.Fact{
					Attribute: attr,
					Subject:   &fact.PeerSubject{Key: pk},
					Expires:   expires,
					Value:     &fact.IPPortValue{IP: ip, Port: port},
				}
				log.Debug("Tracking static fact: %v", staticFact)
				ret = append(ret, staticFact)
			}
		}
	}

	return
}
