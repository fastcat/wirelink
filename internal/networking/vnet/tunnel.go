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
	addrs    []net.IPNet
}

// DetachFromNetwork implements Interface
func (t *Tunnel) DetachFromNetwork() {
	t.m.Lock()
	defer t.m.Unlock()

	t.upstream.Close()
	t.upstream = nil
}

// OutboundPacket implements Interface
func (t *Tunnel) OutboundPacket(p *Packet) {
	t.m.Lock()
	defer t.m.Unlock()

	panic("Not implemented")
}

func (t *Tunnel) selectPeer(p *Packet) *TunPeer {
	panic("Not implemented)")
}

func (t *Tunnel) encapsulate(p *Packet) (*Packet, *TunPeer) {
	if t.upstream == nil || t.upstream.addr == nil {
		return nil, nil
	}
	peer := t.selectPeer(p)
	if peer == nil || peer.endpoint == nil {
		return nil, nil
	}
	return &Packet{
		src:          t.upstream.addr,
		dest:         peer.endpoint,
		encapsulated: p,
	}, peer
}
