package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"
)

// readPackets will process UDP packets from the socket, parse them into facts,
// and send them on the received channel, which it will close when the UDP
// socket is closed.
func (s *LinkServer) readPackets(received chan<- *ReceivedFact) error {
	defer close(received)

	// run the packet reader in the background
	packets := make(chan *networking.UDPPacket, 1)
	rCtx, rCancel := context.WithCancel(s.ctx)
	defer rCancel()
	s.AddHandler(func(ctx context.Context) error {
		return s.conn.ReadPackets(rCtx, fact.UDPMaxSafePayload*2, packets)
	})

	for packet := range packets {
		// reader will filter out timeouts for us, anything left we give up
		if packet.Err != nil {
			return fmt.Errorf("failed to read from UDP socket, giving up: %w", packet.Err)
		}

		pp := &fact.Fact{}
		err := pp.DecodeFrom(len(packet.Data), packet.Time, bytes.NewBuffer(packet.Data))
		if err != nil {
			log.Error("Unable to decode fact: %v %v", err, packet.Data)
			continue
		}
		if pp.Attribute == fact.AttributeSignedGroup {
			err = s.processSignedGroup(pp, packet.Addr, packet.Time, received)
			if err != nil {
				log.Error("Unable to process SignedGroup from %v: %v", packet.Addr, err)
			}
		} else {
			// if we had a peerLookup, we could map the source IP to a name here,
			// but creating that is unnecessarily expensive for this rare error
			log.Error("Ignoring unsigned fact from %v", packet.Addr)
		}
	}

	return nil
}

// processSignedGroup takes a single fact with a SignedGroupValue,
// verifies it, if valid parses it into individual facts,
// and emits them to the `packets` channel
func (s *LinkServer) processSignedGroup(
	f *fact.Fact,
	source *net.UDPAddr,
	now time.Time,
	packets chan<- *ReceivedFact,
) error {
	ps, ok := f.Subject.(*fact.PeerSubject)
	if !ok {
		return fmt.Errorf("SignedGroup has non-PeerSubject: %T", f.Subject)
	}
	pv, ok := f.Value.(*fact.SignedGroupValue)
	if !ok {
		return fmt.Errorf("SignedGroup has non-SignedGroupValue: %T", f.Value)
	}

	if !autopeer.AutoAddress(ps.Key).Equal(source.IP) {
		return fmt.Errorf("SignedGroup source %v does not match key %v", source.IP, ps.Key)
	}
	// TODO: check the key is locally known/trusted
	// for now we have a weak indirect version of that based on the trust model checking the source IP

	valid, err := s.signer.VerifyFrom(pv.Nonce, pv.Tag, pv.InnerBytes, &ps.Key)
	if err != nil {
		return fmt.Errorf("failed to validate SignedGroup signature from %s: %w", s.peerName(ps.Key), err)
	} else if !valid {
		// should never get here, verification errors should always make an error
		return fmt.Errorf("unknown error validating SignedGroup")
	}

	inner, err := pv.ParseInner(now)
	if err != nil {
		return fmt.Errorf("unable to parse SignedGroup inner: %w", err)
	}
	// log.Debug("Received SGF of length %d/%d from %v", len(pv.InnerBytes), len(inner), source)
	for _, innerFact := range inner {
		packets <- &ReceivedFact{fact: innerFact, source: *source}
	}
	return nil
}

// chunkReceived takes a continuous stream of ReceivedFacts and lumps them into
// chunks based on a maximum chunk size and a maximum delay time.
func (s *LinkServer) chunkReceived(
	received <-chan *ReceivedFact,
	newFacts chan<- []*ReceivedFact,
	maxChunk int,
) error {
	defer close(newFacts)

	var buffer []*ReceivedFact

	// TODO: using a ticker here is not ideal, as we can't reset its phase to
	// match when we send a chunk downstream, but using a timer involves more
	// boilerplate
	chunkTicker := time.NewTicker(s.ChunkPeriod)
	defer chunkTicker.Stop()

	// send an empty chunk once at startup to prime things
	newFacts <- nil
	lastChunk := time.Now()

	for done := false; !done; {
		sendBuffer := false
		select {
		case p, ok := <-received:
			if !ok {
				// upstream has closed the channel, we're done
				// we don't care much about transmitting the accumulated facts to peers,
				// but we do want to evaluate them so we can report final state
				sendBuffer = len(buffer) > 0
				done = true
				break
			}
			if p != nil {
				buffer = append(buffer, p)
				if len(buffer) >= maxChunk {
					sendBuffer = true
				}
				// TODO: send soon, but not immediately, if we see certain key facts,
				// such as membership or AIP info
			}

		case <-chunkTicker.C:
			sendBuffer = true
		}

		if sendBuffer {
			// bootID swap needs to happen before we emit the buffer so that the alive
			// info we send immediately sees the new data. the point of this is to get
			// peers to re-send us everything they know right away, since they may
			// have thought we received stuff we didn't.

			// make a new boot ID if we were suspended, and thus peer may have sent us
			// stuff we didn't receive
			now := time.Now()
			if now.Before(lastChunk) || now.Sub(lastChunk) > s.ChunkPeriod*2 {
				log.Info("Detected wall clock discontinuity, updating bootID: %v -> %v", lastChunk, now)
				s.newBootID()
			}

			// mark the device state dirty every tick so downstream processors see the
			// new value
			s.dev.Dirty()
			s.interfaceCache.Dirty()

			newFacts <- buffer
			// always make a new buffer after we send it
			buffer = nil
			lastChunk = now
		}
	}

	// deferred close(packets) will wake up downstream
	return nil
}

// pruneRemovedLocalFacts finds the difference between lastLocal and newLocal,
// and returns chunk less any matching facts
func pruneRemovedLocalFacts(chunk, lastLocal, newLocal []*fact.Fact) []*fact.Fact {
	removed := make(map[fact.Key]bool, len(lastLocal))
	for _, f := range lastLocal {
		removed[fact.KeyOf(f)] = true
	}
	for _, f := range newLocal {
		delete(removed, fact.KeyOf(f))
	}
	filtered := make([]*fact.Fact, 0, len(chunk)-len(removed))
	for _, f := range chunk {
		if !removed[fact.KeyOf(f)] {
			filtered = append(filtered, f)
		} else {
			log.Debug("Pruning removed local fact: %v", f)
		}
	}
	return filtered
}

func (s *LinkServer) processChunks(
	newFacts <-chan []*ReceivedFact,
	factsRefreshed chan<- []*fact.Fact,
) error {
	defer close(factsRefreshed)

	var currentFacts []*fact.Fact
	var lastLocalFacts []*fact.Fact

	for chunk := range newFacts {
		now := time.Now()

		uniqueFacts, newLocalFacts, err := s.processOneChunk(currentFacts, lastLocalFacts, chunk, now)
		if err != nil {
			return err
		}
		lastLocalFacts = newLocalFacts
		currentFacts = uniqueFacts

		factsRefreshed <- uniqueFacts
	}

	return nil
}

func (s *LinkServer) processOneChunk(
	currentFacts, lastLocalFacts []*fact.Fact,
	chunk []*ReceivedFact,
	now time.Time,
) (uniqueFacts, newLocalFacts []*fact.Fact, err error) {
	// accumulate all the still valid and newly valid facts
	newFactsChunk := make([]*fact.Fact, 0, len(currentFacts)+len(chunk))
	// add all the not-expired facts
	for _, f := range currentFacts {
		if now.Before(f.Expires) {
			newFactsChunk = append(newFactsChunk, f)
		}
	}

	dev, err := s.dev.State()
	if err != nil {
		// this probably means the interface is down
		// the log message will be printed by the main app as it exits
		return nil, lastLocalFacts, fmt.Errorf("unable to load device info to evaluate trust, giving up: %w", err)
	}
	s.UpdateRouterState(dev, true)

	newLocalFacts, err = s.collectFacts(dev, now)
	if err != nil {
		log.Error("Unable to collect local facts: %v", err)
	}
	// might still have gotten something before the error tho
	if len(newLocalFacts) != 0 {
		newFactsChunk = append(newFactsChunk, newLocalFacts...)
	}
	// only prune if we retrieved local facts without error
	if err == nil {
		// TODO: this may cause us to remove facts received remotely if we used to
		// also source them locally, but no longer do, even if they are still valid remotely.
		// unclear how big an issue this is. at the very least, the remote should
		// eventually re-send them and we'll re-add them, but it might cause
		// service disruptions
		newFactsChunk = pruneRemovedLocalFacts(newFactsChunk, lastLocalFacts, newLocalFacts)
	} else {
		// something went wrong keep original even though we appended the new data to the combined chunk
		newLocalFacts = lastLocalFacts
	}

	s.pl.addPeers(dev.Peers...)

	// TODO: we can cache the config trust to avoid some re-computation
	evaluators := []trust.Evaluator{
		config.CreateTrustEvaluator(s.config.Peers),
	}
	// only use route-based trust if we don't have any static trust config
	haveConfiguredTrust := false
	for _, p := range s.config.Peers {
		if p.Trust != nil {
			haveConfiguredTrust = true
			break
		}
	}
	if !haveConfiguredTrust {
		evaluators = append(evaluators, trust.CreateRouteBasedTrust(dev.Peers))
	}
	// always let known peers tell us endpoints
	evaluators = append(evaluators, trust.CreateKnownPeerTrust(dev.Peers))

	evaluator := trust.CreateComposite(trust.FirstOnly, evaluators...)

	// add all the new not-expired and _trusted_ facts
	for _, rf := range chunk {
		// add to what the peer knows, even if we otherwise discard the information
		s.peerKnowledge.received(rf)

		if now.After(rf.fact.Expires) {
			continue
		}

		level := evaluator.TrustLevel(rf.fact, rf.source)
		known := evaluator.IsKnown(rf.fact.Subject)
		if trust.ShouldAccept(rf.fact.Attribute, known, level) {
			newFactsChunk = append(newFactsChunk, rf.fact)
			// 	log.Debug("Accepting %v", rf)
			// } else {
			// 	log.Debug("Rejecting %v", rf)
		}
	}
	uniqueFacts = fact.MergeList(newFactsChunk)
	// at this point, ignore any prior error we got
	err = nil

	// compare original vs new facts, act on some changes there
	expiredFacts, newFacts := fact.KeysDifference(currentFacts, uniqueFacts)

	// TODO: these debug logs won't be very useful, as the subject/value are
	// stored as strings to make them comparable
	if len(expiredFacts) != 0 {
		log.Debug("Expired some facts: %v", expiredFacts)
	}
	if len(newFacts) != 0 {
		log.Debug("Got new facts: %v", newFacts)
	}

	// if we expire certain important kinds of facts which affect connectivity
	// to peers, we want to get a full refresh to ensure this is not a false
	// expiration due to packet loss or the like.
	expiredCritical := 0
	for _, fk := range expiredFacts {
		switch fk.Attribute {
		case fact.AttributeAllowedCidrV4, fact.AttributeAllowedCidrV6, fact.AttributeMember, fact.AttributeMemberMetadata:
			log.Info("Expiring critical fact: %s", fk.FancyString(s.peerNamer))
			expiredCritical++
		}
	}
	if expiredCritical != 0 {
		log.Info("Expired %d critical facts, updating bootID", expiredCritical)
		// if we expire any critical facts, request a refresh by cycling our boot id
		s.newBootID()
	}

	return
}
