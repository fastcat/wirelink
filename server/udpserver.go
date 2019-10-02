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
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	conn       *net.UDPConn
	addr       net.UDPAddr
	ctrl       *wgctrl.Client
	deviceName string
}

// DefaultPort is used by default, one up from the normal wireguard port
const DefaultPort = 51821

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

	return &LinkServer{
		conn:       conn,
		addr:       addr,
		ctrl:       ctrl,
		deviceName: deviceName,
	}, nil

}

// Close stops the server and closes its socket
func (s *LinkServer) Close() {
	s.conn.Close()
	s.conn = nil
	s.ctrl.Close()
	s.ctrl = nil
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

func (s *LinkServer) BroadcastFacts(timeout time.Duration) (int, []error) {
	dev, err := s.ctrl.Device(s.deviceName)
	if err != nil {
		panic(err)
	}
	facts, err := s.collectFacts(dev)
	if err != nil {
		panic(err)
	}
	return s.broadcastFacts(dev, facts, timeout)
}

// broadcastFacts tries to send every fact to every peer
// it returns the number of sends performed
func (s *LinkServer) broadcastFacts(dev *wgtypes.Device, facts []*fact.Fact, timeout time.Duration) (int, []error) {
	var counter int32
	var wg sync.WaitGroup
	s.conn.SetWriteDeadline(time.Now().Add(timeout))
	errs := make(chan error)
	for _, fact := range facts {
		for _, peer := range dev.Peers {
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
