package server

import (
	"net"
	"os"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/detect"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/trust"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (s *LinkServer) broadcastFactUpdates(factsRefreshed <-chan []*fact.Fact) error {
	// TODO: naming here is confusing with the `newFacts` channel
	for newFacts := range factsRefreshed {
		dev, err := s.deviceState()
		if err != nil {
			// this probably means the interface is down
			// the log message will be printed by the main app as it exits
			return errors.Wrap(err, "Unable to load device state, giving up")
		}

		s.broadcastFactUpdatesOnce(newFacts, dev)
	}

	return nil
}

func (s *LinkServer) broadcastFactUpdatesOnce(newFacts []*fact.Fact, dev *wgtypes.Device) {
	now := time.Now()
	_, errs := s.broadcastFacts(dev.PublicKey, dev.Peers, newFacts, now, s.ChunkPeriod-time.Second)
	if errs != nil {
		// don't print more than a handful of errors
		if len(errs) > 5 {
			log.Error("Failed to send some facts: %v ...", errs)
		} else {
			log.Error("Failed to send some facts: %v", errs)
		}
	}
}

type sendLevel int

const (
	sendNothing sendLevel = iota
	sendPing
	sendFacts
)

func (s *LinkServer) shouldSendTo(p *wgtypes.Peer) sendLevel {
	// don't try to send info to the peer if the wireguard interface doesn't have
	// an endpoint for it: this will just get rejected by the kernel
	if p.Endpoint == nil {
		log.Debug("Don't send to %s: no wg endpoint", s.peerName(p.PublicKey))
		return sendNothing
	}

	// protect against tests mutating config while we read it
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()

	// send everything to trusted peers and routers
	// NOTE: this detects _current_ routers, not peers that are authorized to become
	// routers in the future based on trusted facts that have not yet been applied
	if s.config.Peers.Trust(p.PublicKey, trust.Untrusted) >= trust.AllowedIPs || detect.IsPeerRouter(p) {
		return sendFacts
	}

	// similarly always send if the peer is designated as an exchange point
	if s.config.Peers.IsFactExchanger(p.PublicKey) {
		return sendFacts
	}

	// if neither end is special or chatty, just send pings to keep the connection alive
	if !s.config.Chatty && !s.config.IsRouterNow {
		log.Debug("Don't send to %s: not special, not chatty, not router", s.peerName(p.PublicKey))
		return sendPing
	}

	// past here, remote and/or local are special (chatty, router, trust source, or fact exchanger)
	// in all such cases the goal is full exchange in both directions
	// we send facts if we think they'll get through, or pings if we're trying to establish a connection,
	// and only fall back on nothing if we don't think we can make a connection

	// if the handshake is healthy (and we are chatty and/or router), send all our info to the peer
	if apply.IsHandshakeHealthy(p.LastHandshakeTime) {
		return sendFacts
	}

	// we have an endpoint for the peer, but it isn't healthy yet:
	// send pings until it becomes healthy
	return sendPing
}

func (s *LinkServer) prepareFactsForPeer(p *wgtypes.Peer, facts []*fact.Fact, ga *fact.GroupAccumulator) {
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
		if !s.peerKnowledge.peerNeeds(p, f, s.ChunkPeriod+time.Second) {
			// log.Debug("Peer %s already knows %v", s.peerName(p.PublicKey), f)
			continue
		}
		err := ga.AddFact(f)
		if err != nil {
			log.Error("Unable to add fact to group: %v", err)
		} else {
			log.Debug("Peer %s needs %v", s.peerName(p.PublicKey), f)
			// assume we will successfully send and peer will accept the info
			// if these assumptions are wrong, re-sending more often is unlikely to help
			s.peerKnowledge.upsertSent(p, f)
		}
	}
}

func (s *LinkServer) addPingFor(p *wgtypes.Peer, ping *fact.Fact, ga *fact.GroupAccumulator) {
	var addedPing bool
	var addPingErr error
	// we want alive facts to live for the normal FactTTL, but we want to send them every AlivePeriod
	// so the "forgetting window" is the difference between those
	// we don't need to add the extra ChunkPeriod+1 buffer in this case
	if s.peerKnowledge.peerNeeds(p, ping, s.FactTTL-s.AlivePeriod) {
		log.Debug("Peer %s needs ping", s.peerName(p.PublicKey))
		addPingErr = ga.AddFact(ping)
		addedPing = true
	} else {
		// if we're going to send stuff to the peer anyways, opportunistically
		// include the ping data if it won't result in sending an extra packet
		// so that we don't send another packet again quite so soon
		addedPing, addPingErr = ga.AddFactIfRoom(ping)
		if addedPing {
			log.Debug("Opportunistically sending ping to %s", s.peerName(p.PublicKey))
		}
	}
	if addPingErr != nil {
		log.Error("Unable to add ping fact to group: %v", addPingErr)
	} else if addedPing {
		// assume we will successfully send and peer will accept the info
		// if these assumptions are wrong, re-sending more often is unlikely to help
		s.peerKnowledge.upsertSent(p, ping)
	}
}

// broadcastFacts tries to send every fact to every peer
// it returns the number of sends performed
func (s *LinkServer) broadcastFacts(
	self wgtypes.Key,
	peers []wgtypes.Peer,
	facts []*fact.Fact,
	now time.Time,
	timeout time.Duration,
) (packetsSent int, sendErrors []error) {
	var sg errgroup.Group

	//nolint:errcheck // don't care if this fails
	s.conn.SetWriteDeadline(now.Add(timeout))

	errs := make(chan error)
	ping := &fact.Fact{
		Subject:   &fact.PeerSubject{Key: self},
		Attribute: fact.AttributeAlive,
		Value:     &fact.UUIDValue{UUID: s.bootID},
		Expires:   now.Add(s.FactTTL),
	}

	for i := range peers {
		// avoid closure binding problems
		p := &peers[i]

		sendLevel := s.shouldSendTo(p)
		if sendLevel == sendNothing {
			continue
		}

		ga := fact.NewAccumulator(fact.SignedGroupMaxSafeInnerLength, now)

		if sendLevel >= sendFacts {
			s.prepareFactsForPeer(p, facts, ga)
		}

		s.addPingFor(p, ping, ga)

		signedGroupFacts, err := ga.MakeSignedGroups(s.signer, &p.PublicKey)
		if err != nil {
			log.Error("Unable to sign groups: %v", err)
			continue
		}

		log.Debug("Sending %d SGFs to %s", len(signedGroupFacts), s.peerName(p.PublicKey))
		for j := range signedGroupFacts {
			sgf := signedGroupFacts[j]
			sg.Go(func() error {
				// log.Debug("Sending SGF of length %d to %s", len(sgf.Value.(*fact.SignedGroupValue).InnerBytes), s.peerName(p.PublicKey))
				err := s.sendFact(p, sgf, now)
				errs <- err
				return err
			})
		}
	}

	var wg errgroup.Group
	var counter int32
	var errlist []error
	// two goroutines: one to accumulate results from the senders,
	// the other to close the channel when the sending group finishes so that
	// the first goroutine will end
	wg.Go(func() error {
		for err := range errs {
			if err != nil {
				errlist = append(errlist, err)
			} else {
				counter++
			}
		}
		return nil
	})
	//nolint:errcheck // never returns an error, accumulates into errs instead
	wg.Go(func() error { sg.Wait(); close(errs); return nil })
	//nolint:errcheck
	wg.Wait()

	if len(errlist) != 0 {
		return int(counter), errlist
	}
	return int(counter), nil
}

func (s *LinkServer) sendFact(peer *wgtypes.Peer, f *fact.Fact, now time.Time) error {
	wpb, err := f.MarshalBinaryNow(now)
	if err != nil {
		return err
	}
	addr := net.UDPAddr{
		IP: autopeer.AutoAddress(peer.PublicKey),
		// NOTE: we assume peers use the same port we do
		Port: s.addr.Port,
		Zone: s.addr.Zone,
	}
	sent, err := s.conn.WriteToUDP(wpb, &addr)
	if err != nil {
		// certain errors are expected
		opErr := err.(*net.OpError)
		if sysErr, ok := opErr.Err.(*os.SyscallError); ok && sysErr.Err == syscall.EDESTADDRREQ {
			// this is expected, ignore it
			return nil
		}
		// else
		return errors.Wrapf(err, "Failed to send to peer %s", s.peerName(peer.PublicKey))
	} else if sent != len(wpb) {
		return errors.Errorf("Sent %d instead of %d", sent, len(wpb))
	}
	// else
	return nil
}
