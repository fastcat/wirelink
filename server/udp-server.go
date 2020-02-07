package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/host"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/signing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	bootID      uuid.UUID
	stateAccess *sync.Mutex
	config      *config.Server
	net         networking.Environment
	conn        networking.UDPConn
	addr        net.UDPAddr
	ctrl        internal.WgClient

	eg     *errgroup.Group
	ctx    context.Context
	cancel context.CancelFunc

	// peerKnowledgeSet tracks what is known by each peer to avoid sending them
	// redundant information
	peerKnowledge *peerKnowledgeSet
	peerConfig    *peerConfigSet
	signer        *signing.Signer

	// channel for asking it to print out its current info
	printRequested chan struct{}
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
func Create(ctrl internal.WgClient, config *config.Server) (*LinkServer, error) {
	device, err := ctrl.Device(config.Iface)
	if err != nil {
		return nil, err
	}
	if config.Port <= 0 {
		config.Port = device.ListenPort + 1
	}

	ip := autopeer.AutoAddress(device.PublicKey)
	addr := net.UDPAddr{
		IP:   ip,
		Port: config.Port,
		Zone: device.Name,
	}

	eg, egCtx := errgroup.WithContext(context.Background())
	ctx, cancel := context.WithCancel(egCtx)

	ret := &LinkServer{
		bootID:         uuid.Must(uuid.NewRandom()),
		config:         config,
		net:            nil, // this will be filled in by `Start()`
		conn:           nil, // this will be filled in by `Start()`
		addr:           addr,
		ctrl:           ctrl,
		stateAccess:    new(sync.Mutex),
		eg:             eg,
		ctx:            ctx,
		cancel:         cancel,
		peerKnowledge:  newPKS(),
		peerConfig:     newPeerConfigSet(),
		signer:         signing.New(&device.PrivateKey),
		printRequested: make(chan struct{}, 1),
	}

	return ret, nil
}

// Start makes the server open its listen socket and start all the goroutines
// to receive and process packets
func (s *LinkServer) Start() (err error) {
	var device *wgtypes.Device
	device, err = s.deviceState()
	if err != nil {
		return errors.Wrap(err, "Unable to load device state to initialize server")
	}

	// have to make sure we have the local IPv6-LL address configured before we can use it
	if s.net == nil {
		s.net, err = host.CreateHost()
		if err != nil {
			return err
		}
	}
	if setLL, err := apply.EnsureLocalAutoIP(s.net, device); err != nil {
		return err
	} else if setLL {
		log.Info("Configured IPv6-LL address on local interface")
	}

	if peerips, err := apply.EnsurePeersAutoIP(s.ctrl, device); err != nil {
		return err
	} else if peerips > 0 {
		log.Info("Added IPv6-LL for %d peers", peerips)
	}

	// only listen on the local ipv6 auto address on the specific interface
	s.conn, err = s.net.ListenUDP("udp6", &s.addr)
	if err != nil {
		return err
	}

	err = s.UpdateRouterState(device, false)
	if err != nil {
		return err
	}

	// ok, network resources are initialized, start all the goroutines!

	packets := make(chan *ReceivedFact, MaxChunk)
	s.eg.Go(func() error { return s.readPackets(packets) })

	newFacts := make(chan []*ReceivedFact, 1)
	s.eg.Go(func() error { return s.receivePackets(packets, newFacts, MaxChunk, ChunkPeriod) })

	factsRefreshed := make(chan []*fact.Fact, 1)
	factsRefreshedForBroadcast := make(chan []*fact.Fact, 1)
	factsRefreshedForConfig := make(chan []*fact.Fact, 1)

	s.eg.Go(func() error { return s.processChunks(newFacts, factsRefreshed) })

	s.eg.Go(func() error {
		return multiplexFactChunks(factsRefreshed, factsRefreshedForBroadcast, factsRefreshedForConfig)
	})

	s.eg.Go(func() error { return s.broadcastFactUpdates(factsRefreshedForBroadcast) })

	s.eg.Go(func() error { return s.configurePeers(factsRefreshedForConfig) })

	return nil
}

// AddHandler adds additional handler helpers to the server lifetime,
// such as for signal handling, which are the domain of the main application
func (s *LinkServer) AddHandler(handler func(ctx context.Context) error) {
	s.eg.Go(func() error {
		return handler(s.ctx)
	})
}

// RequestPrint asks the packet receiver to print out the full set of known facts (local and remote)
func (s *LinkServer) RequestPrint() {
	s.printRequested <- struct{}{}
}

// multiplexFactChunks copies values from input to each output. It will only
// work smoothly if the outputs are buffered so that it doesn't block much
func multiplexFactChunks(input <-chan []*fact.Fact, outputs ...chan<- []*fact.Fact) error {
	for _, output := range outputs {
		defer close(output)
	}

	for chunk := range input {
		for _, output := range outputs {
			output <- chunk
		}
	}

	return nil
}

// RequestStop asks the server to stop, but does not wait for this process to complete
func (s *LinkServer) RequestStop() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}

// Stop halts the background goroutines and releases resources associated with
// them, but leaves open some resources associated with the local device so that
// final state can be inspected
func (s *LinkServer) Stop() {
	s.RequestStop()
	if s.eg != nil {
		s.eg.Wait()
	}

	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			log.Error("Failed to close server socket: %v", err)
		}
		s.conn = nil
	}

	// leave eg & ctx around so we can inspect them after stopping
	// s.eg = nil
	// s.ctx = nil
}

// Close stops the server and closes all resources
func (s *LinkServer) Close() {
	s.Stop()
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	if s.ctrl != nil {
		s.ctrl.Close()
		s.ctrl = nil
	}

	if s.net != nil {
		err := s.net.Close()
		if err != nil {
			log.Error("Unable to close network: %v", err)
		}
		s.net = nil
	}

	if s.eg != nil {
		err := s.eg.Wait()
		if err == nil {
			log.Info("Server closed gracefully")
		} else {
			log.Error("Server exiting after failure")
		}
		s.eg = nil
	}
	s.ctx = nil
}

// Wait waits for a running server to end, returning any error if it ended prematurely
func (s *LinkServer) Wait() error {
	err := s.eg.Wait()
	if err != nil {
		return err
	}
	// we could check s.ctx.Err(), but it won't have anything useful in it
	return nil
}

// Address returns the local IP address on which the server listens
func (s *LinkServer) Address() net.IP {
	return s.addr.IP
}

// Port returns the local UDP port on which the server listens and sends
func (s *LinkServer) Port() int {
	return s.addr.Port
}

// Describe returns a textual summary of the server
func (s *LinkServer) Describe() string {
	nodeTypeDesc := "leaf"
	if s.config.IsRouterNow {
		nodeTypeDesc = "router"
	}
	if s.config.AutoDetectRouter {
		nodeTypeDesc += " (auto)"
	}
	nodeModeDesc := "quiet"
	if s.config.Chatty {
		nodeModeDesc = "chatty"
	}
	return fmt.Sprintf("Version %s on {%s} [%v]:%v (%s, %s)",
		internal.Version,
		s.config.Iface,
		s.addr.IP,
		s.addr.Port,
		nodeTypeDesc,
		nodeModeDesc,
	)
}
