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
	"github.com/fastcat/wirelink/peerfacts"
	"github.com/fastcat/wirelink/trust"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	mgr        *apply.Manager
	conn       *net.UDPConn
	addr       net.UDPAddr
	ctrlAccess *sync.Mutex
	ctrl       *wgctrl.Client
	deviceName string
	wait       *sync.WaitGroup
	// sending on endReader will stop the packet reader goroutine
	endReader chan bool
	// the packet reader goroutine sends each packet on the packets channel as it
	// is parsed
	packets chan *ReceivedFact
	// currentFacts holds a snapshot of the current list of known facts _from
	// other peers_ (no local facts here). This is updated by replacing the slice,
	// not by modifying the contents of the slice.
	currentFacts []*fact.Fact
	// newFacts is used for the packet receiver to periodically emit groups of
	// newly received facts when it's time to refresh state
	newFacts chan []*ReceivedFact
	// factsRefreshed is used to send the new value of `currentFacts` each time it
	// is updated
	factsRefreshed chan []*fact.Fact
	// closed tracks if we already ran `Close()`
	closed bool
	// peerKnowledgeSet tracks what is known by each peer to avoid sending them
	// redundant information
	peerKnowledge *peerKnowledgeSet
}

// MaxChunk is the max number of packets to receive before processing them
const MaxChunk = 100

// ChunkPeriod is the max time to wait between processing chunks of received packets and expiring old ones
// TODO: set this based on TTL instead
const ChunkPeriod = 5 * time.Second

// Create starts the server up.
// Have to take a deviceFactory instead of a Device since you can't refresh a device.
// Will take ownership of the wg client and close it when the server is closed
// If port <= 0, will use the wireguard device's listen port plus one
func Create(ctrl *wgctrl.Client, deviceName string, port int) (*LinkServer, error) {
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
		fmt.Println("Configured IPv6-LL address on local interface")
	}

	peerips, err := apply.EnsurePeerAutoIP(ctrl, device)
	if err != nil {
		return nil, err
	}
	if peerips > 0 {
		fmt.Printf("Added IPv6-LL for %d peers\n", peerips)
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
		mgr:            mgr,
		conn:           conn,
		addr:           addr,
		ctrl:           ctrl,
		ctrlAccess:     &sync.Mutex{},
		deviceName:     deviceName,
		wait:           &sync.WaitGroup{},
		endReader:      make(chan bool),
		packets:        make(chan *ReceivedFact, MaxChunk),
		newFacts:       make(chan []*ReceivedFact, 1),
		factsRefreshed: make(chan []*fact.Fact, 1),
		peerKnowledge:  newPKS(),
	}

	ret.wait.Add(1)
	go ret.readPackets()

	ret.wait.Add(1)
	go ret.receivePackets(MaxChunk, ChunkPeriod)

	ret.wait.Add(1)
	go ret.processChunks()

	ret.wait.Add(1)
	go ret.broadcastFactUpdates()

	return ret, nil
}

// Stop halts the background goroutines and releases resources associated with
// them, but leaves open some resources associated with the local device so that
// final state can be inspected
func (s *LinkServer) Stop() {
	if s.conn == nil {
		return
	}
	s.endReader <- true
	s.wait.Wait()
	s.conn.Close()

	s.conn = nil
	s.wait = nil
	s.endReader = nil
	s.packets = nil
	s.newFacts = nil
}

// Close stops the server and closes all resources
func (s *LinkServer) Close() {
	if s.closed {
		return
	}
	s.Stop()
	s.ctrlAccess.Lock()
	defer s.ctrlAccess.Unlock()
	s.ctrl.Close()
	s.ctrl = nil
	s.closed = true
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
	s.ctrlAccess.Lock()
	defer s.ctrlAccess.Unlock()
	return s.ctrl.Device(s.deviceName)
}

// PrintFacts is just a debug tool, it is not concurrency safe and will panic if
// something goes wrong
func (s *LinkServer) PrintFacts() {
	dev, err := s.deviceState()
	if err != nil {
		panic(err)
	}
	facts, err := s.collectFacts(dev)
	if err != nil {
		panic(err)
	}
	facts = append(facts, s.currentFacts...)
	facts = fact.MergeList(facts)
	facts = fact.SortedCopy(facts)
	for _, fact := range facts {
		fmt.Println(fact)
	}
}

func (s *LinkServer) collectFacts(dev *wgtypes.Device) (ret []*fact.Fact, err error) {
	pf, err := peerfacts.DeviceFacts(dev, 30*time.Second)
	if err != nil {
		return
	}
	ret = make([]*fact.Fact, len(pf))
	copy(ret, pf)
	for _, peer := range dev.Peers {
		pf, err = peerfacts.LocalFacts(&peer, 30*time.Second)
		if err != nil {
			return
		}
		ret = append(ret, pf...)
	}
	return
}

// broadcastFacts tries to send every fact to every peer
// it returns the number of sends performed
func (s *LinkServer) broadcastFacts(peers []wgtypes.Peer, facts []*fact.Fact, timeout time.Duration) (int, []error) {
	var counter int32
	var wg sync.WaitGroup
	s.conn.SetWriteDeadline(time.Now().Add(timeout))
	errs := make(chan error)
	for _, f := range facts {
		for i, p := range peers {
			// don't try to send info to the peer if we don't have an endpoint for it
			if p.Endpoint == nil {
				continue
			}
			// don't tell peers things about themselves
			// they won't accept it unless we are a router,
			// the only way this would be useful would be to tell them their external endpoint,
			// but that's only useful if they can tell others and we can't, but if they can tell others,
			// then those others don't need to know it because they are already connected
			if f.Subject == (fact.PeerSubject{Key: p.PublicKey}) {
				continue
			}
			// don't tell peers other things they already know
			if s.peerKnowledge.peerKnows(&p, f, ChunkPeriod+time.Second) {
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

func (s *LinkServer) readPackets() {
	defer close(s.packets)
	defer s.wait.Done()
	// longest possible fact packet is an ipv6 endpoint
	// which is 1(attr) + 1(ttl) + 1(len)+wgtypes.KeyLen + 1(len)+net.IPv6len+2
	var buffer [4 + wgtypes.KeyLen + net.IPv6len + 2]byte
	for {
		select {
		case <-s.endReader:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, addr, err := s.conn.ReadFromUDP(buffer[:])
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					continue
				}
				// TODO: handle read errors better
				panic(err)
			}
			// TODO: parse the packet
			p, err := fact.Deserialize(buffer[:n])
			if err != nil {
				// TODO: report errors better
				fmt.Println(err)
				continue
			}
			pp, err := fact.Parse(p)
			if err != nil {
				// TODO: report errors better
				fmt.Println(err)
				continue
			}
			rcv := &ReceivedFact{fact: pp, source: addr.IP}
			s.packets <- rcv
		}
	}
}

func (s *LinkServer) receivePackets(maxChunk int, chunkPeriod time.Duration) {
	defer s.wait.Done()

	var buffer []*ReceivedFact
	ticker := time.NewTicker(chunkPeriod)

	for done := false; !done; {
		sendBuffer := false
		select {
		case p, ok := <-s.packets:
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
			s.newFacts <- buffer
			buffer = nil
		}
	}

	close(s.newFacts)
}

func (s *LinkServer) processChunks() {
	defer s.wait.Done()

	for chunk := range s.newFacts {
		now := time.Now()
		fmt.Printf("chunk received: %d\n", len(chunk))
		// accumulate all the still valid and newly valid facts
		newFacts := make([]*fact.Fact, 0, len(s.currentFacts)+len(chunk))
		// add all the not-expired facts
		for _, f := range s.currentFacts {
			if now.Before(f.Expires) {
				newFacts = append(newFacts, f)
			}
		}
		// add all the new not-expired and _trusted_ facts
		dev, err := s.deviceState()
		if err != nil {
			// TODO: report error better
			fmt.Printf("Unable to load device info to evaluate trust: %v\n", err)
			continue
		}

		pl := createPeerLookup(dev.Peers)

		evaluator := trust.CreateRouteBasedTrust(dev.Peers)
		for _, rf := range chunk {
			// add to what the peer knows, even if we otherwise discard the information
			s.peerKnowledge.upsertReceived(rf, pl)

			if now.After(rf.fact.Expires) {
				continue
			}

			level := evaluator.TrustLevel(rf.fact, rf.source)
			known := evaluator.IsKnown(rf.fact.Subject)
			if trust.ShouldAccept(rf.fact.Attribute, known, level) {
				newFacts = append(newFacts, rf.fact)
			}
		}
		uniqueFacts := fact.MergeList(newFacts)
		// TODO: this needs to be atomic or mutex'd
		fmt.Printf("replacing facts: %d with %d -> %d\n", len(s.currentFacts), len(newFacts), len(uniqueFacts))
		s.currentFacts = uniqueFacts

		s.factsRefreshed <- uniqueFacts
	}

	close(s.factsRefreshed)
}

func (s *LinkServer) broadcastFactUpdates() {
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
		count, errs := s.broadcastFacts(dev.Peers, facts, ChunkPeriod-time.Second)
		if errs != nil {
			fmt.Println("Failed to send some facts", errs)
		}
		fmt.Printf("Sent %d fact packets\n", count)
		return count, errs
	}

	// broadcast local facts once at startup
	broadcast(nil)

	// TODO: naming here is confusing with the `newFacts` channel
	for newFacts := range s.factsRefreshed {
		broadcast(newFacts)
	}
}
