package vnet

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A Tunnel represents a Wireguard interface, which encapsulates packets
// and sends them via some other interface
type Tunnel struct {
	BaseInterface

	privateKey, publicKey wgtypes.Key
	upstream              *Socket
	peers                 map[string]*TunPeer
}

var _ Interface = &Tunnel{}

// UseKey loads the given private key into the tunnel along with its computed
// public key
func (t *Tunnel) UseKey(privateKey wgtypes.Key) {
	pub := privateKey.PublicKey()
	t.m.Lock()
	t.publicKey = pub
	t.privateKey = privateKey
	t.m.Unlock()
}

// Keys returns the local private and public keys for the tunnel
func (t *Tunnel) Keys() (privateKey, publicKey wgtypes.Key) {
	t.m.Lock()
	privateKey = t.privateKey
	publicKey = t.publicKey
	t.m.Unlock()
	return privateKey, publicKey
}

// PublicKey returns the tunnel's public key
func (t *Tunnel) PublicKey() wgtypes.Key {
	t.m.Lock()
	defer t.m.Unlock()
	return t.publicKey
}

// GenerateKeys makes a new key pair for the tunnel and uses it,
// panicing if generation fails
func (t *Tunnel) GenerateKeys() (privateKey, publicKey wgtypes.Key) {
	var err error
	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}
	publicKey = privateKey.PublicKey()
	t.m.Lock()
	t.privateKey = privateKey
	t.publicKey = publicKey
	t.m.Unlock()
	return privateKey, publicKey
}

// TunPeer represents a simplified version of a wireguard peer,
// with a remote endpoint and a list of IPNets within the tunnel
type TunPeer struct {
	t           *Tunnel
	name        string
	publicKey   wgtypes.Key
	endpoint    *net.UDPAddr
	lastReceive time.Time
	addrs       map[string]net.IPNet
}

// LastReceive gets the time of the last received packet, or zero if never
func (p *TunPeer) LastReceive() time.Time {
	p.t.m.Lock()
	defer p.t.m.Unlock()
	return p.lastReceive
}

// Endpoint returns the current endpoint of the peer
func (p *TunPeer) Endpoint() *net.UDPAddr {
	p.t.m.Lock()
	defer p.t.m.Unlock()
	if p.endpoint == nil {
		return nil
	}
	// copy
	ret := *p.endpoint
	return &ret
}

// Addrs gets a copy of the currently configured addrs
func (p *TunPeer) Addrs() []net.IPNet {
	p.t.m.Lock()
	defer p.t.m.Unlock()
	ret := make([]net.IPNet, 0, len(p.addrs))
	for _, a := range p.addrs {
		ret = append(ret, a)
	}
	return ret
}

// add more getters as needed

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
func (t *Tunnel) AddPeer(name string, publicKey wgtypes.Key, endpoint *net.UDPAddr, addrs []net.IPNet) *TunPeer {
	p := &TunPeer{
		t:         t,
		name:      name,
		publicKey: publicKey,
		endpoint:  endpoint,
		addrs:     map[string]net.IPNet{},
	}
	for _, a := range addrs {
		p.addrs[a.String()] = a
	}
	t.m.Lock()
	t.peers[publicKey.String()] = p
	t.m.Unlock()
	return p
}

// Peers gets a view of the peers map
func (t *Tunnel) Peers() map[string]*TunPeer {
	t.m.Lock()
	ret := make(map[string]*TunPeer, len(t.peers))
	for k, v := range t.peers {
		ret[k] = v
	}
	t.m.Unlock()
	return ret
}

// DelPeer deletes the peer with the given id (String() of its PublicKey) from the tunnel
func (t *Tunnel) DelPeer(id string) {
	t.m.Lock()
	delete(t.peers, id)
	t.m.Unlock()
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
		// NOTE: this doesn't work correctly if you have a "router" peer
		if sourceSubnetMatch(p.encapsulated, peer.addrs) {
			if srcPeer == nil {
				srcPeer = peer
				break
			}
		}
	}
	if srcPeer == nil {
		t.m.Unlock()
		return false
	}

	// update the peer's source endpoint like wireguard does
	srcPeer.endpoint = p.src
	srcPeer.lastReceive = time.Now()
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
