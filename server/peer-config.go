package server

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/detect"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (s *LinkServer) configurePeers(factsRefreshed <-chan []*fact.Fact) error {
	// avoid deconfiguring peers until we've been running long enough
	// for everyone we're connected to to tell us everything
	startTime := time.Now()

	var facts []*fact.Fact
	var ok bool

FACTLOOP:
	for {
		select {

		case facts, ok = <-factsRefreshed:
			if !ok {
				// input closed, we're done
				break FACTLOOP
			}
			now := time.Now()
			log.Debug("Got a new fact set of length %d", len(facts))

			dev, err := s.deviceState()
			if err != nil {
				// this probably means the interface is down
				// the log message will be printed by the main app as it exits
				return fmt.Errorf("unable to load device state, giving up: %w", err)
			}

			s.configurePeersOnce(facts, dev, startTime, now)

		case <-s.printRequested:
			log.Info("%s", s.formatFacts(time.Now(), facts))
		}
	}

	return nil
}

func (s *LinkServer) collectPeerFlags(
	now time.Time,
	dev *wgtypes.Device,
	factsByPeer map[wgtypes.Key][]*fact.Fact,
) (localPeers, removePeer, validPeers map[wgtypes.Key]bool) {
	// track which peers are known to the device, so we know which we should add
	// this assumes that the prior layer has filtered to not include facts for
	// peers we shouldn't add
	localPeers = make(map[wgtypes.Key]bool)
	removePeer = make(map[wgtypes.Key]bool)
	validPeers = make(map[wgtypes.Key]bool)
	// the "self" key is always local and valid
	localPeers[dev.PublicKey] = true
	validPeers[dev.PublicKey] = true

	// statically configured peers are all valid
	for k := range s.config.Peers {
		validPeers[k] = true
	}

	// loop over the local peers once to update their current state flags
	// before we modify anything. this is important for some race conditions
	// where a trust source is going offline.
	for i := range dev.Peers {
		peer := &dev.Peers[i]
		localPeers[peer.PublicKey] = true
		peerFacts, ok := factsByPeer[peer.PublicKey]
		// if we have no info about a local peer, flag it for deletion
		if !ok && !validPeers[peer.PublicKey] {
			removePeer[peer.PublicKey] = true
			log.Debug("Flagging peer %s for removal: not valid", peer.PublicKey)
		}
		// alive check uses 0 for the maxTTL, as we just care whether the alive fact
		// is still valid now
		newAlive, aliveUntil, bootID := s.peerKnowledge.peerAlive(peer.PublicKey)
		ps, _ := s.peerConfig.Get(peer.PublicKey)
		ps = ps.Update(peer, s.peerConfigName(peer.PublicKey), newAlive, aliveUntil, bootID, now, peerFacts, false)
		s.peerConfig.Set(peer.PublicKey, ps)
	}
	// do the same, slightly fake for the local peer
	{
		localPeers[dev.PublicKey] = true
		ps, _ := s.peerConfig.Get(dev.PublicKey)
		ps = ps.Update(
			// fake a live local peer for the local node
			&wgtypes.Peer{
				LastHandshakeTime: now,
				PublicKey:         dev.PublicKey,
				Endpoint:          &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
			},
			s.peerConfigName(dev.PublicKey),
			true,
			now.Add(s.FactTTL),
			&s.bootID,
			now,
			factsByPeer[dev.PublicKey],
			// quiet: no reason to log "changes" to the local peer
			true,
		)
		s.peerConfig.Set(dev.PublicKey, ps)
	}

	// loop over the facts to identify valid and invalid peers from that list
	for peer, factGroup := range factsByPeer {
		// don't flag for removal anything already identified as valid
		if validPeers[peer] {
			continue
		} else if fact.SliceHas(factGroup, func(f *fact.Fact) bool {
			return f.Attribute == fact.AttributeMember || f.Attribute == fact.AttributeMemberMetadata
		}) {
			validPeers[peer] = true
		} else {
			// TODO: maybe only flag this if localPeer[peer], to reduce log noise in some corner cases
			removePeer[peer] = true
			log.Debug("Flagging peer %s for removal from %s: no membership", peer, dev.PublicKey)
		}
	}

	// trim `peerStates` down to just the peers that we might want to know about
	s.peerConfig.Trim(func(k wgtypes.Key) bool {
		// we already added all the peers in s.config.Peers to validPeers, don't need to re-check here
		return factsByPeer[k] != nil || localPeers[k] || validPeers[k]
	})

	return
}

func (s *LinkServer) configurePeersOnce(newFacts []*fact.Fact, dev *wgtypes.Device, startTime, now time.Time) {
	factsByPeer := groupFactsByPeer(newFacts)

	localPeers, removePeer, validPeers := s.collectPeerFlags(now, dev, factsByPeer)

	// don't need the group members to cancel when one of them fails
	var eg errgroup.Group

	// we don't allow deconfigure/delete until we've been running for
	// longer than the fact ttl so that we don't remove config until we have a
	// reasonable shot at having received everything from the network, or if we
	// are a router or a source of allowed IPs
	startedAndNotRouter := now.Sub(startTime) > s.FactTTL && !s.config.IsRouterNow

	selfTrust := s.config.Peers.Trust(dev.PublicKey, trust.Untrusted)

	// deconfigure also requires that we are not listed as an AIP trust source
	allowDeconfigure := startedAndNotRouter && selfTrust < trust.AllowedIPs

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

	// do another loop to actually modify the peer configs
	for i := range dev.Peers {
		peer := &dev.Peers[i]
		// if the peer is valid, update it (important we don't start updating a
		// peer here that we will delete below)
		if validPeers[peer.PublicKey] {
			updatePeer(peer, false)
		}
	}

	// in the second pass, we add new peers where appropriate
	// note that this doesn't handle adding static peers if we haven't loaded any facts for them
	// that should not be a concern in practice, but may produce oddities in unit tests
	for peer := range factsByPeer {
		// don't add peers we already have (or ourselves)
		if localPeers[peer] ||
			// don't add peers for which we don't have a Membership fact (also or ourselves)
			!validPeers[peer] {
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

	// we may want to delete peers that we didn't want to deconfigure above
	allowDelete := startedAndNotRouter && selfTrust < trust.Membership
	// if we are a trusted source of Membership, then we shouldn't have any
	// peers to remove
	if s.config.IsRouterNow || selfTrust >= trust.Membership {
		for peer, r := range removePeer {
			if !r ||
				// during tests we may remove previously valid peers,
				// which can cause confusion as there may still be endpoint facts and such
				// hanging around which cause the removal flag
				!localPeers[peer] {
				continue
			}
			log.Error("BUG detected: trust source wants to remove peer: %s (%v)", s.peerName(peer))
			allowDelete = false
		}
	}
	if allowDelete && len(removePeer) > 0 {
		eg.Go(func() error { return s.deletePeers(dev, removePeer, now) })
	}

	//nolint:errcheck // we don't actually care if any of the routines failed,
	// just that they finished
	eg.Wait()
}

func (s *LinkServer) peerHealthyEnough(now time.Time, key wgtypes.Key) bool {
	pcs, ok := s.peerConfig.Get(key)
	if !ok {
		return false
	}
	// don't trust a peer's info if its alive packet is nearly expired
	isHealthy := pcs.IsHealthy()
	aliveFor := now.Sub(pcs.AliveSince())
	aliveForMin := s.FactTTL + s.ChunkPeriod
	stillAliveFor := pcs.AliveUntil().Sub(now)
	stillAliveForMin := s.ChunkPeriod * 3 / 2
	if !isHealthy ||
		aliveFor < aliveForMin ||
		stillAliveFor <= stillAliveForMin {
		log.Debug("Maybe not safe to delete peers: %s is not healthy (!%v {%v} || %v < %v || %v <= %v)",
			key, isHealthy, pcs.IsAlive(), aliveFor, aliveForMin, stillAliveFor, stillAliveForMin)
		return false
	}
	log.Debug("Healthy enough: %s: %v >= %v && %v > %v",
		key, aliveFor, aliveForMin, stillAliveFor, stillAliveForMin)
	return true
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
	now time.Time,
) (err error) {
	doDelPeers := false
	anyMemberTrust := false
	for pk, pc := range s.config.Peers {
		if pc.Trust == nil || *pc.Trust < trust.Membership {
			continue
		}
		anyMemberTrust = true
		if s.peerHealthyEnough(now, pk) {
			doDelPeers = true
			log.Debug("Safe to delete peers from %s: %s is healthy", dev.PublicKey, pk)
			break
		}
	}

	if !anyMemberTrust {
		// if we're in full-auto mode, check for a router as a trust source
		for _, peer := range dev.Peers {
			if detect.IsPeerRouter(&peer) && s.peerHealthyEnough(now, peer.PublicKey) {
				doDelPeers = true
				log.Debug("Safe to delete peers from %s: %s is healthy (router)", dev.PublicKey, peer)
				break
			}
		}
	}

	if !doDelPeers {
		log.Debug("Not safe to delete peers from %s", dev.PublicKey)
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
		if detect.IsPeerRouter(&peer) && !anyMemberTrust {
			continue
		}
		log.Info("Removing peer: %s", s.peerName(peer.PublicKey))
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey: peer.PublicKey,
			Remove:    true,
		})
		// forget the peer in the config state
		s.peerConfig.Set(peer.PublicKey, nil)
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

func (s *LinkServer) readyForAllowedIPs(
	now time.Time,
	state *apply.PeerConfigState,
	peer *wgtypes.Peer,
) bool {
	return now.Add(s.ChunkPeriod/2).Before(state.AliveUntil()) ||
		s.config.Peers.IsBasic(peer.PublicKey) ||
		state.IsBasic()
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
		if s.readyForAllowedIPs(now, state, peer) {
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

		if state.TimeForNextEndpoint() {
			nextEndpoint := state.NextEndpoint(facts, now)
			if nextEndpoint == nil {
				log.Debug("Time for new EP for %s, but none known", peerName)
			} else if util.UDPEqualIPPort(nextEndpoint, peer.Endpoint) {
				// don't poke the config if it already has the same endpoint, e.g. there is only one known to try
				log.Debug("Time for new EP for %s, but no alternate known", peerName)
			} else {
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

	var addedAIP bool
	pcfg, addedAIP = apply.EnsurePeerAutoIP(peer, pcfg)
	if addedAIP {
		log.Info("Adding IPv6-LL to %s", peerName)
		logged = true
	}

	if pcfg == nil {
		return
	}

	pcfg.UpdateOnly = !allowAdd

	// TODO: this is a hack to make test assertions stable, find a better way
	if log.IsDebug() {
		util.SortIPNetSlice(pcfg.AllowedIPs)
	}

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
