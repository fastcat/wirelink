package server

import (
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/detect"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (s *LinkServer) configurePeers(factsRefreshed <-chan []*fact.Fact) error {
	// avoid deconfiguring peers until we've been running long enough
	// for everyone we're connected to to tell us everything
	startTime := time.Now()

	for newFacts := range factsRefreshed {
		now := time.Now()
		log.Debug("Got a new fact set of length %d", len(newFacts))

		dev, err := s.deviceState()
		if err != nil {
			// this probably means the interface is down
			// the log message will be printed by the main app as it exits
			return errors.Wrap(err, "Unable to load device state, giving up")
		}

		factsByPeer := groupFactsByPeer(newFacts)

		// trim `peerStates` to just the current peers
		s.peerConfig.Trim(func(k wgtypes.Key) bool { _, ok := factsByPeer[k]; return ok })

		// track which peers are known to the device, so we know which we should add
		// this assumes that the prior layer has filtered to not include facts for
		// peers we shouldn't add
		localPeers := make(map[wgtypes.Key]bool)
		removePeer := make(map[wgtypes.Key]bool)
		validPeers := make(map[wgtypes.Key]bool)

		// don't need the group members to cancel when one of them fails
		var eg errgroup.Group

		// we don't allow peers to be deconfigured until we've been running for
		// longer than the fact ttl so that we don't remove config until we have a
		// reasonable shot at having received everything from the network, or if we
		// are a router or a source of allowed IPs
		allowDeconfigure := now.Sub(startTime) > FactTTL &&
			!s.config.IsRouterNow &&
			s.config.Peers.Trust(dev.PublicKey, trust.Untrusted) < trust.AllowedIPs

		// loop over the local peers once to update their current state flags
		// before we modify anything. this is important for some race conditions
		// where a trust source is going offline.
		for i := range dev.Peers {
			peer := &dev.Peers[i]
			localPeers[peer.PublicKey] = true
			_, ok := factsByPeer[peer.PublicKey]
			// if we have no info about a local peer, flag it for deletion
			if !ok {
				removePeer[peer.PublicKey] = true
			}
			// alive check uses 0 for the maxTTL, as we just care whether the alive fact
			// is still valid now
			newAlive, bootID := s.peerKnowledge.peerAlive(peer.PublicKey, 0)
			ps, _ := s.peerConfig.Get(peer.PublicKey)
			ps = ps.Update(peer, s.peerName(peer.PublicKey), newAlive, bootID, now)
			s.peerConfig.Set(peer.PublicKey, ps)
		}

		// loop over the facts to identify valid and invalid peers from that list
		for peer, factGroup := range factsByPeer {
			if !fact.SliceHas(factGroup, func(f *fact.Fact) bool { return f.Attribute == fact.AttributeMember }) {
				validPeers[peer] = true
			} else {
				removePeer[peer] = true
			}
		}

		// do another loop to actually modify the peer configs
		updatePeer := func(peer *wgtypes.Peer, allowAdd bool) {
			factGroup, ok := factsByPeer[peer.PublicKey]
			if !ok {
				// should never get here
				log.Error("BUG detected: updating unknown peer: %s", s.peerName(peer.PublicKey))
				return
			}

			pcs, _ := s.peerConfig.Get(peer.PublicKey)
			eg.Go(func() error {
				newState, err := s.configurePeer(pcs, peer, factGroup, allowDeconfigure, allowAdd)
				// `configurePeer` always returns the new state, even if it also returns an error
				s.peerConfig.Set(peer.PublicKey, newState)
				return err
			})
		}
		for i := range dev.Peers {
			peer := &dev.Peers[i]
			// if the peer is valid, update it (important we don't start updating a
			// peer here that we will delete below)
			if validPeers[peer.PublicKey] {
				updatePeer(peer, false)
			}
		}

		// in the second pass, we add new peers where appropriate
		for peer := range factsByPeer {
			// don't add peers we already have
			if localPeers[peer] {
				continue
			}
			// don't try to configure the local device as its own peer
			if peer == dev.PublicKey {
				continue
			}
			// don't add peers for which we don't have a Membership fact
			if !validPeers[peer] {
				continue
			}
			// should not be possible to have peer in valid and remove sets
			if removePeer[peer] {
				log.Error("BUG detected: have peer both valid and to-delete: %s", s.peerName(peer))
				continue
			}

			log.Info("Adding new local peer %s", s.peerName(peer))
			updatePeer(&wgtypes.Peer{PublicKey: peer}, true)
		}

		// if we are a trusted source of Membership, then we shouldn't have any
		// peers to remove
		if s.config.IsRouterNow || s.config.Peers.Trust(dev.PublicKey, trust.Untrusted) >= trust.Membership {
			for peer, r := range removePeer {
				if r {
					log.Error("BUG detected: trust source wants to remove peer: %s", s.peerName(peer))
					allowDeconfigure = false
				}
			}
		}

		// we may want to delete peers that we didn't want to deconfigure above
		allowDeconfigure = now.Sub(startTime) > FactTTL &&
			!s.config.IsRouterNow &&
			s.config.Peers.Trust(dev.PublicKey, trust.Untrusted) < trust.Membership
		if allowDeconfigure {
			eg.Go(func() error { return s.deletePeers(dev, removePeer) })
		}

		// we don't actually care if any of the routines failed, just that they
		// finished
		eg.Wait()

		s.printFactsIfRequested(dev, newFacts)
	}

	return nil
}

// deletePeers takes a map (mostly a set) of candidate peers to delete, decides
// whether any peer deletion should happen, and deletes the flagged peers that
// are safe to delete. For peer deletion to happen, there needs to be a peer
// with Membership trust that has been online & healthy long enough to believe
// we have all its facts. The caller is responsible for checking the local node
// state for deletion safety, e.g. uptime and local trust mode. For an
// individual peer to be deleted, it needs to be flagged for deletion, and must
// not be statically configured (as it would just get immediately re-added in
// that case).
func (s *LinkServer) deletePeers(
	dev *wgtypes.Device,
	removePeer map[wgtypes.Key]bool,
) (err error) {
	now := time.Now()

	peerHealthyEnough := func(key wgtypes.Key) bool {
		pcs, ok := s.peerConfig.Get(key)
		if !ok {
			return false
		}
		//FIXME: this can go wrong and cause us to delete peers, because facts
		// are allowed to get very close to expiration before being renewed
		if !pcs.IsHealthy() || now.Sub(pcs.AliveSince()) < FactTTL {
			return false
		}
		return true
	}

	doDelPeers := false
	for pk, pc := range s.config.Peers {
		if pc.Trust == nil || *pc.Trust < trust.Membership {
			continue
		}
		if peerHealthyEnough(pk) {
			doDelPeers = true
			break
		}
	}
	if !doDelPeers && !s.config.Peers.AnyTrustedAt(trust.Membership) {
		// if we're in full-auto mode, check for a router as a trust source
		for _, peer := range dev.Peers {
			if detect.IsPeerRouter(&peer) && peerHealthyEnough(peer.PublicKey) {
				doDelPeers = true
				break
			}
		}
	}

	if !doDelPeers {
		return
	}

	var cfg wgtypes.Config
	for _, peer := range dev.Peers {
		if !removePeer[peer.PublicKey] {
			continue
		}
		// don't delete statically configured peers, they'd just get re-added
		if s.config.Peers.Has(peer.PublicKey) {
			continue
		}
		// don't delete routers if we have no other sources of membership trust
		// (i.e. we are in full-auto mode).
		if detect.IsPeerRouter(&peer) && !s.config.Peers.AnyTrustedAt(trust.Membership) {
			continue
		}
		log.Info("Removing peer: %s", s.peerName(peer.PublicKey))
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
			Remove:    true,
		})
	}
	if len(cfg.Peers) != 0 {
		s.stateAccess.Lock()
		defer s.stateAccess.Unlock()
		err = s.ctrl.ConfigureDevice(s.config.Iface, cfg)
		if err != nil {
			log.Error("Unable to delete peers: %v", err)
		}
	}

	return
}

func (s *LinkServer) configurePeer(
	inputState *apply.PeerConfigState,
	peer *wgtypes.Peer,
	facts []*fact.Fact,
	allowDeconfigure bool,
	allowAdd bool,
) (state *apply.PeerConfigState, err error) {
	now := time.Now()
	peerName := s.peerName(peer.PublicKey)
	state = inputState.EnsureNotNil()

	// TODO: make the lock window here smaller
	// only want to take the lock for the regions where we change config
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()

	var pcfg *wgtypes.PeerConfig
	logged := false

	if state.IsHealthy() {
		// don't setup the AllowedIPs until it's healthy and, unless it's basic,
		// alive, as we don't want to start routing traffic to it if it won't
		// accept it and reciprocate.
		// It is intentional that `healthy && !alive` results in doing nothing:
		// this is a transient state that should clear soon, and so we leave it as
		// hysteresis, esp. in case we miss alive pings a little.
		if state.IsAlive() || s.config.Peers.IsBasic(peer.PublicKey) {
			pcfg = apply.EnsureAllowedIPs(peer, facts, pcfg, allowDeconfigure)
			if pcfg != nil && (len(pcfg.AllowedIPs) > 0 || pcfg.ReplaceAllowedIPs) {
				if pcfg.ReplaceAllowedIPs {
					log.Info("Resetting AIPs on peer %s: %d -> %d", peerName, len(peer.AllowedIPs), len(pcfg.AllowedIPs))
				} else {
					log.Info("Adding AIPs to peer %s: %d", peerName, len(pcfg.AllowedIPs))
				}
				logged = true
			}
		}
	} else {
		// we assume caller has set `allowDeconfigure` in awareness of any local
		// node aspects. There should be no harm in deconfiguring a dead router,
		// as it won't work to route packets while it's dead, and we'll reconfigure
		// it as soon as it comes back online.
		if allowDeconfigure {
			pcfg = apply.OnlyAutoIP(peer, pcfg)
			if pcfg != nil && pcfg.ReplaceAllowedIPs {
				log.Info("Restricting peer to be IPv6-LL only: %s", peerName)
				logged = true
			}
		}

		var addedAIP bool
		pcfg, addedAIP = apply.EnsurePeerAutoIP(peer, pcfg)
		if addedAIP {
			log.Info("Adding IPv6-LL to %s", peerName)
			logged = true
		}

		if state.TimeForNextEndpoint() {
			nextEndpoint := state.NextEndpoint(facts, now)
			if nextEndpoint != nil {
				log.Info("Trying EP for %s: %v", peerName, nextEndpoint)
				logged = true
				if pcfg == nil {
					pcfg = &wgtypes.PeerConfig{PublicKey: peer.PublicKey}
				}
				pcfg.Endpoint = nextEndpoint
				// make sure we try to send to the peer on the new endpoint, so that
				// it gets tested and we can look for the health change on the next pass
				s.peerKnowledge.forcePing(s.signer.PublicKey, peer.PublicKey)
			} else {
				log.Debug("Time for ne wEP for %s, but none found", peerName)
			}
		}
	}

	if pcfg == nil {
		return
	}

	pcfg.UpdateOnly = !allowAdd

	log.Debug("Applying peer configuration: %v", *pcfg)
	err = s.ctrl.ConfigureDevice(s.config.Iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{*pcfg},
	})
	if err != nil {
		log.Error("Failed to configure peer %s: %+v: %v", peerName, *pcfg, err)
		return
	} else if !logged {
		log.Info("WAT: applied unknown peer config change to %s: %+v", peerName, *pcfg)
	}

	return
}
