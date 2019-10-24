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
		facts, err := s.collectFacts(dev)
		if err != nil {
			return 0, []error{err}
		}
		facts = fact.MergeList(append(facts, newFacts...))
		count, errs := s.broadcastFacts(dev.PublicKey, dev.Peers, facts, ChunkPeriod-time.Second)
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

func shouldSendTo(p *wgtypes.Peer, factsByPeer map[wgtypes.Key][]*fact.Fact) bool {
	// don't try to send info to the peer if we don't have an endpoint for it
	if p.Endpoint == nil {
		return false
	}
	// also skip sending if the peer is unhealthy and we don't have any endpoints to try
	if !apply.IsHandshakeHealthy(p.LastHandshakeTime) {
		hasEp := false
	FBP:
		for _, f := range factsByPeer[p.PublicKey] {
			switch f.Attribute {
			case fact.AttributeEndpointV4:
				fallthrough
			case fact.AttributeEndpointV6:
				hasEp = true
				break FBP
			}
		}
		if !hasEp {
			return false
		}
	}
	return true
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
		if !shouldSendTo(&p, factsByPeer) {
			continue
		}

		ga := fact.NewAccumulator(fact.SignedGroupMaxSafeInnerLength)
		// we want alive facts to live for the normal FactTTL, but we want to send them every AlivePeriod
		// so the "forgetting window" is the difference between those
		// we don't need to add the extra ChunkPeriod+1 buffer in this case
		if s.peerKnowledge.peerNeeds(&p, pingFact, FactTTL-AlivePeriod) {
			err := ga.AddFact(pingFact)
			if err != nil {
				log.Error("Unable to add ping fact to group: %v", err)
			} else {
				// log.Info("Peer %s needs ping", s.peerName(p.PublicKey))
				// assume we will successfully send and peer will accept the info
				// if these assumptions are wrong, re-sending more often is unlikely to help
				s.peerKnowledge.upsertSent(&p, pingFact)
			}
		}

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
				// log.Info("Peer %s needs %v", s.peerName(p.PublicKey), f)
				// assume we will successfully send and peer will accept the info
				// if these assumptions are wrong, re-sending more often is unlikely to help
				s.peerKnowledge.upsertSent(&p, f)
			}
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
