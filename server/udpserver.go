package server

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/peerfacts"
	"github.com/fastcat/wirelink/trust"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	stateAccess *sync.Mutex
	isRouter    bool
	mgr         *apply.Manager
	conn        *net.UDPConn
	addr        net.UDPAddr
	ctrl        *wgctrl.Client
	deviceName  string
	wait        *sync.WaitGroup
	// sending on endReader will stop the packet reader goroutine
	endReader chan bool
	// closed tracks if we already ran `Close()`
	closed bool
	// peerKnowledgeSet tracks what is known by each peer to avoid sending them
	// redundant information
	peerKnowledge *peerKnowledgeSet
	// counter for asking it to print out its current info
	printsRequested *int32
	// folks listening for notification that we have closed
	stopWatchers []chan<- bool
}

// MaxChunk is the max number of packets to receive before processing them
const MaxChunk = 100

// ChunkPeriod is the max time to wait between processing chunks of received packets and expiring old ones
// TODO: set this based on TTL instead
const ChunkPeriod = 5 * time.Second

// FactTTL is the TTL we apply to any locally generated Facts
const FactTTL = 30 * time.Second

// Create starts the server up.
// Have to take a deviceFactory instead of a Device since you can't refresh a device.
// Will take ownership of the wg client and close it when the server is closed
// If port <= 0, will use the wireguard device's listen port plus one
func Create(ctrl *wgctrl.Client, deviceName string, port int, isRouter bool) (*LinkServer, error) {
	device, err := ctrl.Device(deviceName)
	if err != nil {
		return nil, err
	}
	if port <= 0 {
		port = device.ListenPort + 1
	}

	// have to make sure we have the local IPv6-LL address configured before we can use it
	mgr, err := apply.NewManager()
	if err != nil {
		return nil, err
	}
	setll, err := mgr.EnsureLocalAutoIP(device)
	if err != nil {
		return nil, err
	}
	if setll {
		log.Info("Configured IPv6-LL address on local interface")
	}

	peerips, err := apply.EnsurePeerAutoIP(ctrl, device)
	if err != nil {
		return nil, err
	}
	if peerips > 0 {
		log.Info("Added IPv6-LL for %d peers", peerips)
	}

	ip := autopeer.AutoAddress(device.PublicKey)
	addr := net.UDPAddr{
		IP:   ip,
		Port: port,
		Zone: device.Name,
	}
	// only listen on the local ipv6 auto address on the specific interface
	conn, err := net.ListenUDP("udp6", &addr)
	if err != nil {
		return nil, err
	}

	ret := &LinkServer{
		isRouter:        isRouter,
		mgr:             mgr,
		conn:            conn,
		addr:            addr,
		ctrl:            ctrl,
		stateAccess:     new(sync.Mutex),
		deviceName:      deviceName,
		wait:            new(sync.WaitGroup),
		endReader:       make(chan bool),
		peerKnowledge:   newPKS(),
		printsRequested: new(int32),
	}

	packets := make(chan *ReceivedFact, MaxChunk)
	ret.wait.Add(1)
	go ret.readPackets(ret.endReader, packets)

	newFacts := make(chan []*ReceivedFact, 1)
	ret.wait.Add(1)
	go ret.receivePackets(packets, newFacts, MaxChunk, ChunkPeriod)

	factsRefreshed := make(chan []*fact.Fact, 1)
	factsRefreshedForBroadcast := make(chan []*fact.Fact, 1)
	factsRefreshedForConfig := make(chan []*fact.Fact, 1)

	ret.wait.Add(1)
	go ret.processChunks(newFacts, factsRefreshed)

	ret.wait.Add(1)
	go multiplexFactChunks(ret.wait, factsRefreshed, factsRefreshedForBroadcast, factsRefreshedForConfig)

	ret.wait.Add(1)
	go ret.broadcastFactUpdates(factsRefreshedForBroadcast)

	ret.wait.Add(1)
	go ret.configurePeers(factsRefreshedForConfig)

	return ret, nil
}

// RequestPrint asks the packet receiver to print out the full set of known facts (local and remote)
func (s *LinkServer) RequestPrint() {
	atomic.AddInt32(s.printsRequested, 1)
}

// multiplexFactChunks copies values from input to each output. It will only
// work smoothly if the outputs are buffered so that it doesn't block much
func multiplexFactChunks(wg *sync.WaitGroup, input <-chan []*fact.Fact, outputs ...chan<- []*fact.Fact) {
	defer wg.Done()
	for _, output := range outputs {
		defer close(output)
	}

	for chunk := range input {
		for _, output := range outputs {
			output <- chunk
		}
	}
}

// Stop halts the background goroutines and releases resources associated with
// them, but leaves open some resources associated with the local device so that
// final state can be inspected
func (s *LinkServer) Stop() {
	s.stop(true)
}

func (s *LinkServer) onError(err error) {
	go s.stop(false)
}

func (s *LinkServer) stop(normal bool) {
	if s.conn == nil {
		return
	}
	s.endReader <- true
	s.wait.Wait()
	s.conn.Close()

	s.conn = nil
	s.wait = nil
	s.endReader = nil

	for _, stopWatcher := range s.stopWatchers {
		stopWatcher <- normal
	}
}

// Close stops the server and closes all resources
func (s *LinkServer) Close() {
	if s.closed {
		return
	}
	s.Stop()
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	s.ctrl.Close()
	s.ctrl = nil
	s.closed = true
}

// OnStopped creates and returns a channel that will emit a single bool when the server is stopped
// it will emit `true` if the server stopped by normal request, or `false` if it failed with an error
func (s *LinkServer) OnStopped() <-chan bool {
	c := make(chan bool, 1)
	s.stateAccess.Lock()
	s.stopWatchers = append(s.stopWatchers, c)
	s.stateAccess.Unlock()
	return c
}

// Address returns the local IP address on which the server listens
func (s *LinkServer) Address() net.IP {
	return s.addr.IP
}

// Port returns the local UDP port on which the server listens and sends
func (s *LinkServer) Port() int {
	return s.addr.Port
}

// deviceState does a mutex-protected access to read the current state of the
// wireguard device
func (s *LinkServer) deviceState() (dev *wgtypes.Device, err error) {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	return s.ctrl.Device(s.deviceName)
}

func (s *LinkServer) collectFacts(dev *wgtypes.Device) (ret []*fact.Fact, err error) {
	pf, err := peerfacts.DeviceFacts(dev, FactTTL)
	if err != nil {
		return
	}
	ret = make([]*fact.Fact, len(pf))
	copy(ret, pf)
	for _, peer := range dev.Peers {
		pf, err = peerfacts.LocalFacts(&peer, FactTTL)
		if err != nil {
			return
		}
		ret = append(ret, pf...)
	}
	return
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
	for i, p := range peers {
		// don't try to send info to the peer if we don't have an endpoint for it
		if p.Endpoint == nil {
			continue
		}
		// always send an "I'm here" pseudo-fact
		wg.Add(1)
		go s.sendFact(&peers[i], pingFact, &wg, &counter, errs)
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
			wg.Add(1)
			// can't use &p here because we get the loop var instead of the array element
			go s.sendFact(&peers[i], f, &wg, &counter, errs)
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

	// assume peers know things we send them
	// if they ignore us, sending it again is not going to help
	s.peerKnowledge.upsertSent(peer, f)
}

func (s *LinkServer) readPackets(endReader <-chan bool, packets chan<- *ReceivedFact) {
	defer s.wait.Done()
	defer close(packets)

	// longest possible fact packet is an ipv6 endpoint
	// which is 1(attr) + 1(ttl) + 1(len)+wgtypes.KeyLen + 1(len)+net.IPv6len+2
	var buffer [4 + wgtypes.KeyLen + net.IPv6len + 2]byte
	for {
		select {
		case <-endReader:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := s.conn.ReadFromUDP(buffer[:])
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					continue
				}
				log.Error("Failed to read from socket, giving up: %v", err)
				s.onError(err)
				break
			}
			p, err := fact.Deserialize(buffer[:n])
			if err != nil {
				log.Error("Unable to deserialize fact: %v", err)
				continue
			}
			pp, err := fact.Parse(p)
			if err != nil {
				log.Error("Unable to parse fact: %v", err)
				continue
			}
			rcv := &ReceivedFact{fact: pp, source: addr.IP}
			packets <- rcv
		}
	}
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
			buffer = append(buffer, p)
			if len(buffer) >= maxChunk {
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

func (s *LinkServer) processChunks(
	newFacts <-chan []*ReceivedFact,
	factsRefreshed chan<- []*fact.Fact,
) {
	defer s.wait.Done()
	defer close(factsRefreshed)

	var currentFacts []*fact.Fact

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

		pl := createPeerLookup(dev.Peers)

		evaluator := trust.CreateRouteBasedTrust(dev.Peers)
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

		s.printFactsIfRequested(dev, uniqueFacts)
	}
}

func (s *LinkServer) printFactsIfRequested(dev *wgtypes.Device, facts []*fact.Fact) {
	printsRequested := atomic.LoadInt32(s.printsRequested)
	if printsRequested == 0 {
		return
	}
	defer atomic.CompareAndSwapInt32(s.printsRequested, printsRequested, 0)

	localFacts, err := s.collectFacts(dev)
	if err != nil {
		log.Error("Unable to load facts: %v", err)
		// note that we do NOT kill the server in this case
		return
	}
	// safe to mutate our private localFacts, but not the shared facts we received
	facts = fact.SortedCopy(fact.MergeList(append(localFacts, facts...)))
	str := "Current facts"
	for _, fact := range facts {
		str += "\n"
		str += fact.String()
	}
	log.Info("%s", str)
}

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

func (s *LinkServer) configurePeers(factsRefreshed <-chan []*fact.Fact) {
	defer s.wait.Done()

	peerStates := make(map[wgtypes.Key]*apply.PeerConfigState)

	// the first chunk we get is usually pretty incomplete
	// avoid deconfiguring peers until we get a second chunk
	firstRefresh := false

	for newFacts := range factsRefreshed {
		dev, err := s.deviceState()
		if err != nil {
			// this probably means the interface is down
			log.Error("Unable to load device state, giving up: %v", err)
			s.onError(err)
		}

		allFacts, err := s.collectFacts(dev)
		if err != nil {
			log.Error("Unable to collect local facts, skipping peer config: %v", err)
			continue
		}
		// it's safe for us to mutate the facts list from the local device,
		// but not the one from the channel
		allFacts = fact.MergeList(append(allFacts, newFacts...))

		// group facts by peer
		factsByPeer := make(map[wgtypes.Key][]*fact.Fact)
		for _, f := range allFacts {
			ps, ok := f.Subject.(*fact.PeerSubject)
			if !ok {
				// WAT
				log.Error("WAT: fact subject is a %T: %v", f.Subject, f)
				continue
			}
			factsByPeer[ps.Key] = append(factsByPeer[ps.Key], f)
		}

		// trim `peerStates` to just the current peers
		for k := range peerStates {
			if _, ok := factsByPeer[k]; !ok {
				delete(peerStates, k)
			}
		}

		wg := new(sync.WaitGroup)
		psm := new(sync.Mutex)
		for i := range dev.Peers {
			peer := &dev.Peers[i]
			fg, ok := factsByPeer[peer.PublicKey]
			if !ok {
				continue
			}
			psm.Lock()
			ps := peerStates[peer.PublicKey]
			psm.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				// TODO: inspect returned error?
				newState, _ := s.configurePeer(ps, peer, fg, !firstRefresh)
				psm.Lock()
				peerStates[peer.PublicKey] = newState
				psm.Unlock()
			}()
		}
		wg.Wait()

		firstRefresh = false
	}
}

func (s *LinkServer) configurePeer(
	inputState *apply.PeerConfigState,
	peer *wgtypes.Peer,
	facts []*fact.Fact,
	allowDeconfigure bool,
) (state *apply.PeerConfigState, err error) {
	state = inputState.Update(peer, s.peerKnowledge.peerAlive(peer, ChunkPeriod))

	// TODO: make the lock window here smaller
	// only want to take the lock for the regions where we change config
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()

	if state.IsHealthy() {
		// don't setup the AllowedIPs until it's both healthy and alive,
		// as we don't want to start routing traffic to it if it won't accept it
		// and reciprocate
		if state.IsAlive() {
			added, err := apply.EnsureAllowedIPs(s.ctrl, s.deviceName, peer, facts)
			if err != nil {
				log.Error("Failed to update peer AllowedIPs: %v", err)
			} else if added > 0 {
				log.Info("Added AIPs to peer %v: %d", peer.PublicKey, added)
			}
		}
		return
	}

	if !allowDeconfigure {
		return
	}

	// on a router, we are the network's memory of the AllowedIPs, so we must not
	// clear them, but on leaf devices we should remove them from the peer when
	// we don't have a direct connection so that the peer is reachable through a
	// router. for much the same reason, we don't want to remove AllowedIPs from
	// routers.
	// TODO: IsRouter doesn't belong in trust
	if !s.isRouter && !trust.IsRouter(peer) {
		changed, err := apply.OnlyAutoIP(s.ctrl, s.deviceName, peer)
		if err != nil {
			log.Error("Failed to restrict peer to IPv6-LL only: %v", err)
		} else if changed {
			log.Info("Peer is now IPv6-LL only: %v", peer.PublicKey)
		}
	}

	if !state.TimeForNextEndpoint() {
		// not time to try another endpoint yet
		return
	}

	nextEndpoint := state.NextEndpoint(facts)
	if nextEndpoint == nil {
		return
	}

	log.Info("Trying EP for %v: %v", peer.PublicKey, nextEndpoint)

	err = s.ctrl.ConfigureDevice(s.deviceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			wgtypes.PeerConfig{
				PublicKey: peer.PublicKey,
				Endpoint:  nextEndpoint,
			},
		},
	})
	if err != nil {
		log.Error("Failed to configure EP for %v: %v: %v", peer.PublicKey, nextEndpoint, err)
		return
	}

	return
}
