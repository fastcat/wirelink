package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/signing"
	"github.com/google/uuid"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	bootID      uuid.UUID
	stateAccess *sync.Mutex
	config      *config.Server
	mgr         *apply.Manager
	conn        *net.UDPConn
	addr        net.UDPAddr
	ctrl        *wgctrl.Client
	wait        *sync.WaitGroup
	// sending on endReader will stop the packet reader goroutine
	endReader chan bool
	// closed tracks if we already ran `Close()`
	closed bool
	// peerKnowledgeSet tracks what is known by each peer to avoid sending them
	// redundant information
	peerKnowledge *peerKnowledgeSet
	peerConfig    *peerConfigSet
	signer        *signing.Signer
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

// AlivePeriod is how often we send "I'm here" facts to peers
const AlivePeriod = 30 * time.Second

// FactTTL is the TTL we apply to any locally generated Facts
// This is only meaningful if it is <= 255 seconds, since we encode the TTL as a byte
const FactTTL = 255 * time.Second

// Create starts the server up.
// Have to take a deviceFactory instead of a Device since you can't refresh a device.
// Will take ownership of the wg client and close it when the server is closed
// If port <= 0, will use the wireguard device's listen port plus one
func Create(ctrl *wgctrl.Client, config *config.Server) (*LinkServer, error) {
	device, err := ctrl.Device(config.Iface)
	if err != nil {
		return nil, err
	}
	if config.Port <= 0 {
		config.Port = device.ListenPort + 1
	}

	// have to make sure we have the local IPv6-LL address configured before we can use it
	mgr, err := apply.NewManager()
	if err != nil {
		return nil, err
	}
	defer mgr.Close()
	setLL, err := mgr.EnsureLocalAutoIP(device)
	if err != nil {
		return nil, err
	}
	if setLL {
		log.Info("Configured IPv6-LL address on local interface")
	}

	peerips, err := apply.EnsurePeersAutoIP(ctrl, device)
	if err != nil {
		return nil, err
	}
	if peerips > 0 {
		log.Info("Added IPv6-LL for %d peers", peerips)
	}

	ip := autopeer.AutoAddress(device.PublicKey)
	addr := net.UDPAddr{
		IP:   ip,
		Port: config.Port,
		Zone: device.Name,
	}
	// only listen on the local ipv6 auto address on the specific interface
	conn, err := net.ListenUDP("udp6", &addr)
	if err != nil {
		return nil, err
	}

	ret := &LinkServer{
		bootID:          uuid.Must(uuid.NewRandom()),
		config:          config,
		mgr:             mgr,
		conn:            conn,
		addr:            addr,
		ctrl:            ctrl,
		stateAccess:     new(sync.Mutex),
		wait:            new(sync.WaitGroup),
		endReader:       make(chan bool),
		peerKnowledge:   newPKS(),
		peerConfig:      newPeerConfigSet(),
		signer:          signing.New(&device.PrivateKey),
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
