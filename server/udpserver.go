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

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/peerfacts"
	"github.com/fastcat/wirelink/trust"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	conn       *net.UDPConn
	addr       net.UDPAddr
	ctrl       *wgctrl.Client
	deviceName string
	wait       *sync.WaitGroup
	// sending on this channel will stop the packet reader goroutine
	endReader chan bool
	// the packet reader goroutine emits each packet as it is parsed on this channel
	packets chan *ReceivedFact
	// the current list of known facts _from other peers_ (no local facts here)
	currentFacts []*fact.Fact
	// the packet receiver will periodically emit groups of new facts here when it's time to refresh state
	newFacts chan []*ReceivedFact
	// sends a copy of the new value of `currentFacts` each time it is updated
	factsRefreshed chan []*fact.Fact
}

// DefaultPort is used by default, one up from the normal wireguard port
const DefaultPort = 51821

// MaxChunk is the max number of packets to receive before processing them
const MaxChunk = 100

// ChunkPeriod is the max time to wait between processing chunks of received packets and expiring old ones
// TODO: set this based on TTL instead
const ChunkPeriod = 5 * time.Second

// Create starts the server up.
// Have to take a deviceFactory instead of a Device since you can't refresh a device.
// Will take ownership of the wg client and close it when the server is closed
func Create(ctrl *wgctrl.Client, deviceName string, port int) (*LinkServer, error) {
	if port <= 0 {
		port = DefaultPort
	}
	device, err := ctrl.Device(deviceName)
	if err != nil {
		return nil, err
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
		conn:           conn,
		addr:           addr,
		ctrl:           ctrl,
		deviceName:     deviceName,
		wait:           &sync.WaitGroup{},
		endReader:      make(chan bool),
		packets:        make(chan *ReceivedFact, 10),
		newFacts:       make(chan []*ReceivedFact, 1),
		factsRefreshed: make(chan []*fact.Fact),
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

// Close stops the server and closes its socket
func (s *LinkServer) Close() {
	s.endReader <- true
	s.wait.Wait()
	s.conn.Close()
	s.ctrl.Close()
	s.conn = nil
	s.ctrl = nil
	s.wait = nil
	s.endReader = nil
	s.packets = nil
	s.newFacts = nil
}

// Address returns the local IP address on which the server listens
func (s *LinkServer) Address() net.IP {
	return s.addr.IP
}

// Port returns the local UDP port on which the server listens and sends
func (s *LinkServer) Port() int {
	return s.addr.Port
}

// PrintFacts is just a debug tool, it will panic if something goes wrong
func (s *LinkServer) PrintFacts() {
	dev, err := s.ctrl.Device(s.deviceName)
	if err != nil {
		panic(err)
	}
	facts, err := s.collectFacts(dev)
	if err != nil {
		panic(err)
	}
	for _, fact := range facts {
		printFact(fact)
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

func printFact(f *fact.Fact) {
	fmt.Printf("%v\n", f)
	wf, err := f.ToWire()
	if err != nil {
		panic(err)
	}
	wfd, err := wf.Serialize()
	if err != nil {
		panic(err)
	}
	fmt.Printf("  => (%d) %v\n", len(wfd), wfd)
	dwfd, err := fact.Deserialize(wfd)
	if err != nil {
		panic(err)
	}
	pf, err := fact.Parse(dwfd)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  ==> %v\n", pf)
}

// broadcastFacts tries to send every fact to every peer
// it returns the number of sends performed
func (s *LinkServer) broadcastFacts(peers []wgtypes.Peer, facts []*fact.Fact, timeout time.Duration) (int, []error) {
	var counter int32
	var wg sync.WaitGroup
	s.conn.SetWriteDeadline(time.Now().Add(timeout))
	errs := make(chan error)
	for _, fact := range facts {
		for _, peer := range peers {
			pa := autopeer.AutoAddress(peer.PublicKey)
			wg.Add(1)
			go s.sendFact(pa, fact, &wg, &counter, errs)
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

func (s *LinkServer) sendFact(ip net.IP, fact *fact.Fact, wg *sync.WaitGroup, counter *int32, errs chan<- error) {
	defer wg.Done()
	wp, err := fact.ToWire()
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
		IP:   ip,
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

	for {
		sendBuffer := false
		select {
		case p, ok := <-s.packets:
			if !ok {
				// don't care about any pending facts at this point, this is the quit signal
				close(s.newFacts)
				return
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
		dev, err := s.ctrl.Device(s.deviceName)
		if err != nil {
			// TODO: report error better
			fmt.Printf("Unable to load device info to evaluate trust: %v\n", err)
		} else {
			trust := trust.CreateRouteBasedTrust(dev.Peers)
			for _, rf := range chunk {
				if now.Before(rf.fact.Expires) && trust.IsTrusted(rf.fact, rf.source) {
					newFacts = append(newFacts, rf.fact)
				}
			}
			// TODO: this needs to be atomic or mutex'd
			fmt.Printf("replacing facts: %d with %d\n", len(s.currentFacts), len(newFacts))
			s.currentFacts = newFacts

			s.factsRefreshed <- newFacts
		}
	}

	close(s.factsRefreshed)
}

func (s *LinkServer) broadcastFactUpdates() {
	defer s.wait.Done()

	// TODO: should we fire this off into a goroutine when we call it?
	broadcast := func(newFacts []*fact.Fact) (int, []error) {
		dev, err := s.ctrl.Device(s.deviceName)
		if err != nil {
			return 0, []error{err}
		}
		facts, err := s.collectFacts(dev)
		if err != nil {
			return 0, []error{err}
		}
		facts = append(facts, newFacts...)
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
