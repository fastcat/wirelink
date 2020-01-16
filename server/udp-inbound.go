package server

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"
)

func (s *LinkServer) readPackets(endReader <-chan bool, packets chan<- *ReceivedFact) {
	defer s.wait.Done()
	defer close(packets)

	var buffer [fact.UDPMaxSafePayload * 2]byte
	for {
		select {
		case <-endReader:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := s.conn.ReadFromUDP(buffer[:])
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// send a nil to wake up the processor in case it has other work to do
					packets <- nil
					continue
				}
				log.Error("Failed to read from socket, giving up: %v", err)
				s.onError(err)
				break
			}
			pp := &fact.Fact{}
			err = pp.DecodeFrom(n, bytes.NewBuffer(buffer[:n]))
			if err != nil {
				log.Error("Unable to decode fact: %v %v", err, buffer[:n])
				continue
			}
			if pp.Attribute == fact.AttributeSignedGroup {
				err = s.processGroup(pp, addr, packets)
				if err != nil {
					log.Error("Unable to process SignedGroup from %v: %v", *addr, err)
				}
			} else {
				// if we had a peerLookup, we could map the source IP to a name here,
				// but creating that is unnecessarily expensive for this rare error
				log.Error("Ignoring unsigned fact from %v", *addr)
				// rcv := &ReceivedFact{fact: pp, source: *addr}
				// packets <- rcv
			}
		}
	}
}

func (s *LinkServer) processGroup(f *fact.Fact, source *net.UDPAddr, packets chan<- *ReceivedFact) error {
	ps, ok := f.Subject.(*fact.PeerSubject)
	if !ok {
		return fmt.Errorf("SignedGroup has non-PeerSubject: %T", f.Subject)
	}
	pv, ok := f.Value.(*fact.SignedGroupValue)
	if !ok {
		return fmt.Errorf("SignedGroup has non-SigendGroupValue: %T", f.Value)
	}

	if !autopeer.AutoAddress(ps.Key).Equal(source.IP) {
		return fmt.Errorf("SignedGroup source %v does not match key %v", source.IP, ps.Key)
	}
	// TODO: check the key is locally known/trusted
	// for now we have a weak indirect version of that based on the trust model checking the source IP

	valid, err := s.signer.VerifyFrom(pv.Nonce, pv.Tag, pv.InnerBytes, &ps.Key)
	if err != nil {
		return errors.Wrapf(err, "Failed to validate SignedGroup signature from %s", s.peerName(ps.Key))
	} else if !valid {
		// should never get here, verification errors should always make an error
		return fmt.Errorf("Unknown error validating SignedGroup")
	}

	inner, err := pv.ParseInner()
	if err != nil {
		return errors.Wrapf(err, "Unable to parse SignedGroup inner")
	}
	for _, innerFact := range inner {
		packets <- &ReceivedFact{fact: innerFact, source: *source}
	}
	return nil
}

func (s *LinkServer) receivePackets(
	packets <-chan *ReceivedFact,
	newFacts chan<- []*ReceivedFact,
	maxChunk int,
	chunkPeriod time.Duration,
) {
	defer s.wait.Done()
	defer close(newFacts)

	var buffer []*ReceivedFact
	ticker := time.NewTicker(chunkPeriod)

	// send an empty chunk once at startup to prime things
	newFacts <- nil

	for done := false; !done; {
		sendBuffer := false
		select {
		case p, ok := <-packets:
			if !ok {
				// we don't care about transmitting the accumulated facts to peers,
				// but we do want to evaluate them so we can report final state
				sendBuffer = true
				done = true
				break
			}
			if p != nil {
				buffer = append(buffer, p)
				if len(buffer) >= maxChunk {
					sendBuffer = true
				}
			}
			// push the buffer through if state report is requested so that it happens quickly
			// don't need to use the atomic load here, as the worst case is a delay in printing
			if *s.printsRequested != 0 {
				sendBuffer = true
			}
		case <-ticker.C:
			sendBuffer = true
		}

		if sendBuffer {
			newFacts <- buffer
			// always make a new buffer after we send it
			buffer = nil
		}
	}
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
) {
	defer s.wait.Done()
	defer close(factsRefreshed)

	var currentFacts []*fact.Fact
	var lastLocalFacts []*fact.Fact

	for chunk := range newFacts {
		now := time.Now()
		// accumulate all the still valid and newly valid facts
		newFactsChunk := make([]*fact.Fact, 0, len(currentFacts)+len(chunk))
		// add all the not-expired facts
		for _, f := range currentFacts {
			if now.Before(f.Expires) {
				newFactsChunk = append(newFactsChunk, f)
			}
		}
		dev, err := s.deviceState()
		if err != nil {
			log.Error("Unable to load device info to evaluate trust, giving up: %v", err)
			s.onError(err)
			continue
		}

		localFacts, err := s.collectFacts(dev)
		if err != nil {
			log.Error("Unable to collect local facts: %v", err)
		}
		// might still have gotten something before the error tho
		if len(localFacts) != 0 {
			newFactsChunk = append(newFactsChunk, localFacts...)
		}
		// only prune if we retrieved local facts without error
		if err == nil {
			newFactsChunk = pruneRemovedLocalFacts(newFactsChunk, lastLocalFacts, localFacts)
			lastLocalFacts = localFacts
		}

		pl := createPeerLookup(dev.Peers)

		evaluator := trust.CreateComposite(trust.FirstOnly,
			// TODO: we can cache the config trust to avoid some re-computation
			config.CreateTrustEvaluator(s.config.Peers),
			trust.CreateRouteBasedTrust(dev.Peers),
		)
		// add all the new not-expired and _trusted_ facts
		for _, rf := range chunk {
			// add to what the peer knows, even if we otherwise discard the information
			s.peerKnowledge.upsertReceived(rf, pl)

			if now.After(rf.fact.Expires) {
				continue
			}

			level := evaluator.TrustLevel(rf.fact, rf.source)
			known := evaluator.IsKnown(rf.fact.Subject)
			if trust.ShouldAccept(rf.fact.Attribute, known, level) {
				newFactsChunk = append(newFactsChunk, rf.fact)
			}
		}
		uniqueFacts := fact.MergeList(newFactsChunk)
		// TODO: log new/removed facts, ignoring TTL
		currentFacts = uniqueFacts

		factsRefreshed <- uniqueFacts
	}
}
