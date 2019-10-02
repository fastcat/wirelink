package server

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/peerfacts"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	conn       *net.UDPConn
	addr       net.IP
	port       int
	ctrl       *wgctrl.Client
	deviceName string
}

// DefaultPort is used by default, one up from the normal wireguard port
const DefaultPort = 51821

// Create starts the server up
// have to take a deviceFactory instead of a Device since you can't refresh a device
func Create(ctrl *wgctrl.Client, deviceName string, port int) (*LinkServer, error) {
	if port <= 0 {
		port = DefaultPort
	}
	device, err := ctrl.Device(deviceName)
	if err != nil {
		return nil, err
	}
	addr := autopeer.AutoAddress(device.PublicKey)
	// only listen on the local ipv6 auto address on the specific interface
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{
		IP:   addr,
		Port: port,
		Zone: device.Name,
	})
	if err != nil {
		return nil, err
	}

	return &LinkServer{
		conn:       conn,
		addr:       addr,
		port:       port,
		ctrl:       ctrl,
		deviceName: deviceName,
	}, nil

}

// Close stops the server and closes its socket
func (s *LinkServer) Close() {
	s.conn.Close()
	s.conn = nil
}

// Address returns the local IP address on which the server listens
func (s *LinkServer) Address() net.IP {
	return s.addr
}

// Port returns the local UDP port on which the server listens and sends
func (s *LinkServer) Port() int {
	return s.port
}

// PrintFacts is just a debug tool, it will panic if something goes wrong
func (s *LinkServer) PrintFacts() {
	facts, err := s.collectFacts()
	if err != nil {
		panic(err)
	}
	for _, fact := range facts {
		printFact(fact)
	}
}

func (s *LinkServer) collectFacts() (ret []*fact.Fact, err error) {
	dev, err := s.ctrl.Device(s.deviceName)
	if err != nil {
		return
	}
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
