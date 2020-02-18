package vnet

import (
	"net"
)

// A Tunnel represents a Wireguard interface, which encapsulates packets
// and sends them via some other interface
type Tunnel struct {
	BaseInterface

	upstream *Socket
	peers    map[string]*TunPeer
}

var _ Interface = &Tunnel{}

// TunPeer represents a simplified version of a wireguard peer,
// with a remote endpoint and a list of IPNets within the tunnel
type TunPeer struct {
	id       string
	endpoint *net.UDPAddr
	addrs    map[string]net.IPNet
}

// DetachFromNetwork implements Interface
func (t *Tunnel) DetachFromNetwork() {
	t.m.Lock()
	defer t.m.Unlock()

	if t.upstream != nil {
		t.upstream.Close()
		t.upstream = nil
	}
}

// Listen tells the tunnel to open a listening socket on the host on which it
// can receive encapsulated packets
func (t *Tunnel) Listen(port int) {
	t.DetachFromNetwork()

	t.m.Lock()
	t.upstream = t.host.AddSocket(&net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	})
	t.upstream.rx = t.receiveEncapsulated
	t.m.Unlock()
}

// AddPeer defines a new valid peer for communicating over the tunnel
func (t *Tunnel) AddPeer(id string, endpoint *net.UDPAddr, addrs []net.IPNet) *TunPeer {
	p := &TunPeer{
		id:       id,
		endpoint: endpoint,
		addrs:    map[string]net.IPNet{},
	}
	for _, a := range addrs {
		p.addrs[a.String()] = a
	}
	t.m.Lock()
	t.peers[id] = p
	t.m.Unlock()
	return p
}

func (t *Tunnel) receiveEncapsulated(p *Packet) bool {
	if p.encapsulated == nil {
		return false
	}
	// TODO: include src & dest tun ids in the packet and verify those match

	t.m.Lock()
	var srcPeer *TunPeer
	// find a peer with an addr that matches the packet source
	for _, peer := range t.peers {
		if sourceSubnetMatch(p.encapsulated, peer.addrs) {
			srcPeer = peer
			break
		}
	}
	if srcPeer == nil {
		t.m.Unlock()
		return false
	}

	// update the peer's source endpoint like wireguard does
	srcPeer.endpoint = p.src
	t.m.Unlock()

	// try to deliver it to a socket
	return t.InboundPacket(p.encapsulated)
}

// OutboundPacket implements Interface
func (t *Tunnel) OutboundPacket(p *Packet) bool {
	t.m.Lock()
	upstream := t.upstream
	if upstream == nil {
		t.m.Unlock()
		return false
	}
	// no routing in this model, if the destination is not on a connected subnet,
	// not going to send it
	if !destinationSubnetMatch(p, t.addrs) {
		t.m.Unlock()
		return false
	}
	// TODO: bogon detection (src addr match)?

	var dest *net.UDPAddr
	for _, peer := range t.peers {
		if peer.endpoint != nil && destinationSubnetMatch(p, peer.addrs) {
			dest = peer.endpoint
			break
		}
	}
	t.m.Unlock()

	if dest == nil {
		return false
	}

	ep := &Packet{
		src:          t.upstream.addr,
		dest:         dest,
		encapsulated: p,
	}
	return upstream.OutboundPacket(ep)
}
