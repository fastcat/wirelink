package server

import (
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/fastcat/wirelink/autopeer"
)

// LinkServer represents the server component of wirelink
// sending/receiving on a socket
type LinkServer struct {
	conn *net.UDPConn
	addr net.IP
}

// DefaultPort is used by default, one up from the normal wireguard port
const DefaultPort = 51821

// Create starts the server up
func Create(device *wgtypes.Device, port int) (*LinkServer, error) {
	if port <= 0 {
		port = DefaultPort
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
		conn: conn,
		addr: addr,
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
