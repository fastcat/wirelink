// Package server provides the core class that implements the wirelink server,
// exchanging UDP packets with other peers on the same wireguard network.
package server

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/config"
	"github.com/fastcat/wirelink/device"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/log"
	"github.com/fastcat/wirelink/signing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	bootIDValue atomic.Value
	config      *config.Server
	net         networking.Environment
	conn        networking.UDPConn
	addr        net.UDPAddr
	dev         *device.Device

	eg     *errgroup.Group
	ctx    context.Context
	cancel context.CancelFunc

	pl *peerLookup

	// peerKnowledgeSet tracks what is known by each peer to avoid sending them
	// redundant information
	peerKnowledge *peerKnowledgeSet
	peerConfig    *peerConfigSet
	signer        *signing.Signer

	// channel for asking it to print out its current info
	printRequested chan struct{}

	// TODO: these should not be exported like this
	// this is temporary to simplify acceptance tests

	FactTTL     time.Duration
	ChunkPeriod time.Duration
	AlivePeriod time.Duration

	interfaceCache *interfaceCache
}

// MaxChunk is the max number of packets to receive before processing them
const MaxChunk = 100

// DefaultChunkPeriod is the default max time to wait between processing chunks
// of received packets and expiring old ones
// TODO: set this based on TTL instead
const DefaultChunkPeriod = 5 * time.Second

// DefaultAlivePeriod is how often we send "I'm here" facts to peers
const DefaultAlivePeriod = 30 * time.Second

// DefaultFactTTL is the default TTL we apply to any locally generated Facts
const DefaultFactTTL = 255 * time.Second

// Create prepares a new server object, but does not start it yet.
// Will take ownership of the wg client and close it when the server is closed.
// The default listen port is the wireguard listen port plus one.
func Create(
	env networking.Environment,
	ctrl internal.WgClient,
	config *config.Server,
) (*LinkServer, error) {
	dev, err := device.Take(ctrl, config.Iface)
	if err != nil {
		return nil, err
	}
	devState, _ := dev.State()
	if config.Port <= 0 {
		config.Port = devState.ListenPort + 1
	}

	ip := autopeer.AutoAddress(devState.PublicKey)
	addr := net.UDPAddr{
		IP:   ip,
		Port: config.Port,
		Zone: config.Iface,
	}

	ic, err := newInterfaceCache(env, config.Iface)
	if err != nil {
		return nil, err
	}

	eg, egCtx := errgroup.WithContext(context.Background())
	ctx, cancel := context.WithCancel(egCtx)

	pl := newPeerLookup()

	ret := &LinkServer{
		config: config,
		net:    env,
		conn:   nil, // this will be filled in by `Start()`
		addr:   addr,
		dev:    dev,

		eg:     eg,
		ctx:    ctx,
		cancel: cancel,

		pl: pl,

		peerKnowledge:  newPKS(pl),
		peerConfig:     newPeerConfigSet(),
		signer:         signing.New(devState.PrivateKey),
		printRequested: make(chan struct{}, 1),

		FactTTL:     DefaultFactTTL,
		ChunkPeriod: DefaultChunkPeriod,
		AlivePeriod: DefaultAlivePeriod,

		interfaceCache: ic,
	}
	ret.newBootID()

	return ret, nil
}

func (s *LinkServer) newBootID() {
	s.bootIDValue.Store(uuid.Must(uuid.NewRandom()))
}

func (s *LinkServer) bootID() uuid.UUID {
	return s.bootIDValue.Load().(uuid.UUID)
}

// Start makes the server open its listen socket and start all the goroutines
// to receive and process packets
func (s *LinkServer) Start() (err error) {
	var device *wgtypes.Device
	device, err = s.dev.State()
	if err != nil {
		return fmt.Errorf("unable to load device state to initialize server: %w", err)
	}

	// have to make sure we have the local IPv6-LL address configured before we can use it
	if setLL, err := apply.EnsureLocalAutoIP(s.net, device); err != nil {
		return err
	} else if setLL {
		log.Info("Configured IPv6-LL address on local interface")
	}

	if peerips, err := s.dev.EnsurePeersAutoIP(); err != nil {
		return err
	} else if peerips > 0 {
		log.Info("Added IPv6-LL for %d peers", peerips)
	}

	// only listen on the local ipv6 auto address on the specific interface
	s.conn, err = s.net.ListenUDP("udp6", &s.addr)
	if err != nil {
		return err
	}

	s.UpdateRouterState(device, false)

	// ok, network resources are initialized, start all the goroutines!

	received := make(chan *ReceivedFact, MaxChunk)
	s.eg.Go(func() error { return s.readPackets(received) })

	newFacts := make(chan []*ReceivedFact, 1)
	s.eg.Go(func() error { return s.chunkReceived(received, newFacts, MaxChunk) })

	factsRefreshed := make(chan []*fact.Fact, 1)
	factsRefreshedForBroadcast := make(chan []*fact.Fact, 1)
	factsRefreshedForConfig := make(chan []*fact.Fact, 1)

	s.eg.Go(func() error { return s.processChunks(newFacts, factsRefreshed) })

	s.eg.Go(func() error {
		// TODO: the multiplex / racing makes reliable acceptance tests hard,
		// as it can cause it to take a second fact ttl for things to expire
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
	}
}

// Stop halts the background goroutines and releases resources associated with
// them, but leaves open some resources associated with the local device so that
// final state can be inspected
func (s *LinkServer) Stop() {
	s.RequestStop()
	if s.eg != nil {
		//nolint:errcheck // we know this is going to be a cancellation error
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

	s.cancel = nil
}

// Close stops the server and closes all resources
func (s *LinkServer) Close() {
	s.Stop()
	if s.dev != nil {
		if err := s.dev.Close(); err != nil {
			log.Error("Failed to close device interface: %v", err)
		}
		s.dev = nil
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
