package server

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (s *LinkServer) broadcastFactUpdates(factsRefreshed <-chan []*fact.Fact) {
	defer s.wait.Done()

	// TODO: should we fire this off into a goroutine when we call it?
	broadcast := func(newFacts []*fact.Fact) (int, []error) {
		dev, err := s.deviceState()
		if err != nil {
			return 0, []error{err}
		}
		count, errs := s.broadcastFacts(dev.PublicKey, dev.Peers, newFacts, ChunkPeriod-time.Second)
		if errs != nil {
			// don't print more than a handful of errors
			if len(errs) > 5 {
				log.Error("Failed to send some facts: %v ...", errs)
			} else {
				log.Error("Failed to send some facts: %v", errs)
			}
		}
		return count, errs
	}

	// broadcast local facts once at startup
	broadcast(nil)

	// TODO: naming here is confusing with the `newFacts` channel
	for newFacts := range factsRefreshed {
		// error printing is handled inside `broadcast`, so we ignore the return
		broadcast(newFacts)
	}
}

type sendLevel int

const (
	sendNothing sendLevel = iota
	sendPing
	sendFacts
)

func (s *LinkServer) shouldSendTo(p *wgtypes.Peer, factsByPeer map[wgtypes.Key][]*fact.Fact) sendLevel {
	// don't try to send info to the peer if the wireguard interface doesn't have
	// an endpoint for it: this will just get rejected by the kernel
	if p.Endpoint == nil {
		log.Debug("Don't send to %s: no wg endpoint", s.peerName(p.PublicKey))
		return sendNothing
	}

	// if the peer is a router or otherwise has elevated trust, always try to send
	// this is partly to address problems where we wake from sleep and everything is stale
	// and we don't talk to anyone to refresh anything
	if s.config.Peers.Trust(p.PublicKey, trust.Untrusted) >= trust.AllowedIPs {
		return sendFacts
	}

	// similarly always send if the peer is designated as an exchange point
	if s.config.Peers.IsFactExchanger(p.PublicKey) {
		return sendFacts
	}

	// if we are not operating in chatty mode and we are not special, stop here
	if !s.config.Chatty && !s.config.IsRouter {
		log.Debug("Don't send to %s: not special, not chatty, not router", s.peerName(p.PublicKey))
		return sendPing
	}

	// if the handshake is healthy (and we are chatty and/or router), send all our info to the peer
	if apply.IsHandshakeHealthy(p.LastHandshakeTime) {
		return sendFacts
	}

	// if we know some endpoint to try, try to ping to activate the handshake
	// the fact set will go through later
	for _, f := range factsByPeer[p.PublicKey] {
		switch f.Attribute {
		case fact.AttributeEndpointV4:
			fallthrough
		case fact.AttributeEndpointV6:
			return sendPing
		}
	}

	// peer is unhealthy and not likely to become so without help from someone else,
	// don't waste time trying to send to it
	log.Debug("Don't send to %s: unhealty and no endpoints", s.peerName(p.PublicKey))
	return sendNothing
}

// broadcastFacts tries to send every fact to every peer
// it returns the number of sends performed
func (s *LinkServer) broadcastFacts(self wgtypes.Key, peers []wgtypes.Peer, facts []*fact.Fact, timeout time.Duration) (int, []error) {
	var counter int32
	var wg sync.WaitGroup

	s.conn.SetWriteDeadline(time.Now().Add(timeout))

	errs := make(chan error)
	pingFact := &fact.Fact{
		Subject:   &fact.PeerSubject{Key: self},
		Attribute: fact.AttributeUnknown,
		Value:     fact.EmptyValue{},
		Expires:   time.Now().Add(FactTTL),
	}

	factsByPeer := groupFactsByPeer(facts)

	for i, p := range peers {
		sendLevel := s.shouldSendTo(&p, factsByPeer)
		if sendLevel == sendNothing {
			continue
		}

		ga := fact.NewAccumulator(fact.SignedGroupMaxSafeInnerLength)

		if sendLevel >= sendFacts {
			for _, f := range facts {
				// don't tell peers things about themselves
				// they won't accept it unless we are a router,
				// the only way this would be useful would be to tell them their external endpoint,
				// but that's only useful if they can tell others and we can't, but if they can tell others,
				// then those others don't need to know it because they are already connected
				if ps, ok := f.Subject.(*fact.PeerSubject); ok && *ps == (fact.PeerSubject{Key: p.PublicKey}) {
					continue
				}
				// don't tell peers other things they already know
				if !s.peerKnowledge.peerNeeds(&p, f, ChunkPeriod+time.Second) {
					continue
				}
				err := ga.AddFact(f)
				if err != nil {
					log.Error("Unable to add fact to group: %v", err)
				} else {
					log.Debug("Peer %s needs %v", s.peerName(p.PublicKey), f)
					// assume we will successfully send and peer will accept the info
					// if these assumptions are wrong, re-sending more often is unlikely to help
					s.peerKnowledge.upsertSent(&p, f)
				}
			}
		}

		addedPing := false
		var addPingErr error
		// we want alive facts to live for the normal FactTTL, but we want to send them every AlivePeriod
		// so the "forgetting window" is the difference between those
		// we don't need to add the extra ChunkPeriod+1 buffer in this case
		if s.peerKnowledge.peerNeeds(&p, pingFact, FactTTL-AlivePeriod) {
			log.Debug("Peer %s needs ping", s.peerName(p.PublicKey))
			addPingErr = ga.AddFact(pingFact)
			addedPing = true
		} else {
			// if we're going to send stuff to the peer anyways, opportunistically
			// include the ping data if it won't result in sending an extra packet
			// so that we don't send another packet again quite so soon
			addedPing, addPingErr = ga.AddFactIfRoom(pingFact)
			if addedPing {
				log.Debug("Opportunistically sending ping to %s", s.peerName(p.PublicKey))
			}
		}
		if addPingErr != nil {
			log.Error("Unable to add ping fact to group: %v", addPingErr)
		} else if addedPing {
			// assume we will successfully send and peer will accept the info
			// if these assumptions are wrong, re-sending more often is unlikely to help
			s.peerKnowledge.upsertSent(&p, pingFact)
		}

		sgfs, err := ga.MakeSignedGroups(s.signer, &p.PublicKey)
		if err != nil {
			log.Error("Unable to sign groups: %v", err)
			continue
		}

		for j := range sgfs {
			wg.Add(1)
			// have to use &arr[idx] here because we don't want to bind the loop var
			go s.sendFact(&peers[i], &sgfs[j], &wg, &counter, errs)
		}
	}

	go func() { wg.Wait(); close(errs) }()
	var errlist []error
	for err := range errs {
		errlist = append(errlist, err)
	}
	if len(errlist) != 0 {
		return int(counter), errlist
	}
	return int(counter), nil
}

func (s *LinkServer) sendFact(peer *wgtypes.Peer, f *fact.Fact, wg *sync.WaitGroup, counter *int32, errs chan<- error) {
	defer wg.Done()
	wp, err := f.ToWire()
	if err != nil {
		errs <- err
		return
	}
	wpb, err := wp.Serialize()
	if err != nil {
		errs <- err
		return
	}
	addr := net.UDPAddr{
		IP:   autopeer.AutoAddress(peer.PublicKey),
		Port: s.addr.Port,
		Zone: s.addr.Zone,
	}
	sent, err := s.conn.WriteToUDP(wpb, &addr)
	if err != nil {
		// certain errors are expected
		nerr := err.(*net.OpError)
		if serr, ok := nerr.Err.(*os.SyscallError); ok && serr.Err == syscall.EDESTADDRREQ {
			// this is expected, ignore it
			err = nil
		} else {
			errs <- err
			return
		}
	} else if sent != len(wpb) {
		errs <- fmt.Errorf("Sent %d instead of %d", sent, len(wpb))
		return
	}

	// else/fall-through: sent OK
	atomic.AddInt32(counter, 1)
}
