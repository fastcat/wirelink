package server

import (
	"net"
	"path/filepath"
	"time"

	"github.com/fastcat/wirelink/config"
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
	ret, err = peerfacts.DeviceFacts(dev, FactTTL, s.shouldReportIface, s.config)
	if err != nil {
		return
	}

	// facts the local node knows about peers configured in the wireguard device
	//FIXME: find a better way to figure out if we should trust our local AIP list
	useLocalAIPs := s.config.IsRouterNow || s.config.Peers.Trust(dev.PublicKey, trust.Untrusted) >= trust.AddPeer
	log.Debug("Using local AIP facts: %v", useLocalAIPs)
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
		ret = s.handlePeerConfigAllowedIPs(pk, pc, expires, ret)
		// skip endpoint lookups for self
		// if other peers need these as static facts, they would have it in their config
		if pk != dev.PublicKey {
			ret = s.handlePeerConfigEndpoints(pk, pc, expires, ret)
		}
	}

	return
}

func (s *LinkServer) handlePeerConfigAllowedIPs(
	pk wgtypes.Key,
	pc *config.Peer,
	expires time.Time,
	currentFacts []*fact.Fact,
) (facts []*fact.Fact) {
	facts = currentFacts
	for _, aip := range pc.AllowedIPs {
		nip := util.NormalizeIP(aip.IP)
		attr := fact.AttributeUnknown
		if len(nip) == net.IPv4len {
			attr = fact.AttributeAllowedCidrV4
		} else if len(nip) == net.IPv6len {
			attr = fact.AttributeAllowedCidrV6
		}
		if attr != fact.AttributeUnknown {
			staticFact := &fact.Fact{
				Attribute: attr,
				Subject:   &fact.PeerSubject{Key: pk},
				Expires:   expires,
				Value:     &fact.IPNetValue{IPNet: aip},
			}
			// not worth logging this, it will happen on every loop
			// log.Debug("Tracking static fact: %v", staticFact)
			facts = append(facts, staticFact)
		}
	}
	return
}

func (s *LinkServer) handlePeerConfigEndpoints(
	pk wgtypes.Key,
	pc *config.Peer,
	expires time.Time,
	currentFacts []*fact.Fact,
) (facts []*fact.Fact) {
	facts = currentFacts

	// only do static lookups for dead peers
	if pcs, ok := s.peerConfig.Get(pk); ok && (pcs.IsAlive() || pcs.IsHealthy()) {
		log.Debug("Skipping static lookup for OK peer %s", s.peerName(pk))
		return
	}

	for _, ep := range pc.Endpoints {
		ips, err := net.LookupIP(ep.Host)
		if err != nil {
			// DNS lookup errors are generally transient and not worth logging
			continue
		}
		if len(ips) == 0 {
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
				Value:     &fact.IPPortValue{IP: ip, Port: ep.Port},
			}
			log.Debug("Tracking static fact: %v", staticFact)
			facts = append(facts, staticFact)
		}
	}
	return
}
