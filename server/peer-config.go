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

		// don't need the group members to cancel when one of them fails
		var eg errgroup.Group

		// we don't allow peers to be deconfigured until we've been running for longer than the fact ttl
		// so that we don't remove config until we have a reasonable shot at having received everything
		// from the network
		allowDeconfigure := time.Now().Sub(startTime) > FactTTL

		// loop over the peers once to update their current state flags before we modify anything
		// this is important for some race conditions where a trust source is going offline
		for i := range dev.Peers {
			peer := &dev.Peers[i]
			localPeers[peer.PublicKey] = true
			// alive check uses 0 for the maxTTL, as we just care whether the alive fact
			// is still valid now
			newAlive, bootID := s.peerKnowledge.peerAlive(peer.PublicKey, 0)
			ps, _ := s.peerConfig.Get(peer.PublicKey)
			ps = ps.Update(peer, s.peerName(peer.PublicKey), newAlive, bootID)
			s.peerConfig.Set(peer.PublicKey, ps)
		}

		// do another loop to actually modify the peer configs
		updatePeer := func(peer *wgtypes.Peer, allowAdd bool) {
			fg, ok := factsByPeer[peer.PublicKey]
			if !ok {
				removePeer[peer.PublicKey] = true
				return
			}
			ps, _ := s.peerConfig.Get(peer.PublicKey)
			eg.Go(func() error {
				newState, err := s.configurePeer(ps, &dev.PublicKey, peer, fg, allowDeconfigure, allowAdd)
				// `configurePeer` always returns the new state, even if it also returns an error
				s.peerConfig.Set(peer.PublicKey, newState)
				return err
			})
		}
		for i := range dev.Peers {
			peer := &dev.Peers[i]
			updatePeer(peer, false)
		}

		// add peers for which we have trusted facts but which are not present in the local device
		for peer := range factsByPeer {
			if localPeers[peer] {
				continue
			}
			if peer == dev.PublicKey {
				// don't try to configure the local device as its own peer
				continue
			}
			// don't delete if if we're adding it
			delete(removePeer, peer)
			// have to make a fake local peer for this, thankfully this is pretty trivial
			log.Info("Adding new local peer %s", s.peerName(peer))
			updatePeer(&wgtypes.Peer{
				PublicKey: peer,
			}, true)
		}

		if allowDeconfigure {
			eg.Go(func() error { return s.deletePeers(dev, removePeer) })
		}

		// we don't actually care if any of the routines failed, just need to wait for all of them
		eg.Wait()

		s.printFactsIfRequested(dev, newFacts)
	}

	return nil
}

func (s *LinkServer) deletePeers(
	dev *wgtypes.Device,
	removePeer map[wgtypes.Key]bool,
) (err error) {
	// only run peer deletion if we have a peer with DelPeer trust online
	// and it has been online for longer than the fact TTL so that we are
	// reasonably sure we have all the data from it ... and we are not a router
	doDelPeers := false
	if !s.config.IsRouterNow {
		now := time.Now()
		for pk, pc := range s.config.Peers {
			if pc.Trust == nil || *pc.Trust < trust.DelPeer {
				continue
			}
			pcs, ok := s.peerConfig.Get(pk)
			if !ok {
				continue
			}
			//FIXME: this can go wrong and cause us to delete peers, because facts
			// are allowed to get very close to expiration before being renewed
			if !pcs.IsHealthy() || now.Sub(pcs.AliveSince()) < FactTTL {
				continue
			}
			doDelPeers = true
			break
		}
	}

	if doDelPeers {
		var cfg wgtypes.Config
		for _, peer := range dev.Peers {
			if !removePeer[peer.PublicKey] {
				continue
			}
			// never delete routers
			if detect.IsPeerRouter(&peer) {
				continue
			}
			// never delete fact exchangers
			if s.config.Peers.IsFactExchanger(peer.PublicKey) {
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
	}

	return
}

func (s *LinkServer) configurePeer(
	inputState *apply.PeerConfigState,
	self *wgtypes.Key,
	peer *wgtypes.Peer,
	facts []*fact.Fact,
	allowDeconfigure bool,
	allowAdd bool,
) (state *apply.PeerConfigState, err error) {
	peerName := s.peerName(peer.PublicKey)
	state = inputState.EnsureNotNil()

	// TODO: make the lock window here smaller
	// only want to take the lock for the regions where we change config
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()

	var pcfg *wgtypes.PeerConfig
	logged := false

	//TODO: maybe should mask `allowDeconfigure` with `!s.config.IsRouter && !trust.IsRouter(peer)`?
	// just as we don't want to restrict a peer to auto-ip-only if either end is a router,
	// we also may not want to do any allowedip restrictions in that case.
	// For now, this is probably saved because we will have facts for all the existing allowed ips,
	// and so they should never be considered for removal.
	// Also, allowing AIP edits of routers enables more live reconfig use cases.

	if state.IsHealthy() {
		// don't setup the AllowedIPs until it's healthy and, unless it's basic, alive,
		// as we don't want to start routing traffic to it if it won't accept it
		// and reciprocate.
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
		if allowDeconfigure {
			// on a router, we are the network's memory of the AllowedIPs, so we must not
			// clear them, but on leaf devices we should remove them from the peer when
			// we don't have a direct connection so that the peer is reachable through a
			// router. for much the same reason, we don't want to remove AllowedIPs from
			// routers.
			// TODO: IsRouter doesn't belong in trust
			if !s.config.IsRouterNow && !detect.IsPeerRouter(peer) {
				pcfg = apply.OnlyAutoIP(peer, pcfg)
				if pcfg != nil && pcfg.ReplaceAllowedIPs {
					log.Info("Restricting peer to be IPv6-LL only: %s", peerName)
					logged = true
				}
			}
		}

		var addedAIP bool
		pcfg, addedAIP = apply.EnsurePeerAutoIP(peer, pcfg)
		if addedAIP {
			log.Info("Adding IPv6-LL to %s", peerName)
			logged = true
		}

		if state.TimeForNextEndpoint() {
			nextEndpoint := state.NextEndpoint(facts)
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
