package vnet

import (
	"net"

	"github.com/pkg/errors"

	"github.com/fastcat/wirelink/internal"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type hostWgClient struct {
	h *Host
}

var _ internal.WgClient = &hostWgClient{}

func (he *hostEnvironment) NewWgClient() (internal.WgClient, error) {
	return &hostWgClient{he.h}, nil
}

func (hc *hostWgClient) Close() error {
	hc.h = nil
	return nil
}

func (hc *hostWgClient) Devices() ([]*wgtypes.Device, error) {
	hc.h.m.Lock()

	// have to queue up tunnels list since we need to switch locks when doing the wrapping
	var tunnels []*Tunnel
	for _, i := range hc.h.interfaces {
		if t, ok := i.(*Tunnel); ok {
			tunnels = append(tunnels, t)
		}
	}
	hc.h.m.Unlock()

	ret := make([]*wgtypes.Device, 0, len(tunnels))
	for _, t := range tunnels {
		ret = append(ret, t.AsWgDevice())
	}
	return ret, nil
}

func (hc *hostWgClient) Device(name string) (*wgtypes.Device, error) {
	hc.h.m.Lock()

	i := hc.h.interfaces[name]
	if i == nil {
		hc.h.m.Unlock()
		// TODO: model real error better
		return nil, errors.New("No such device")
	}
	t, ok := i.(*Tunnel)
	if !ok {
		hc.h.m.Unlock()
		return nil, errors.New("Not a wireguard device")
	}

	hc.h.m.Unlock()

	return t.AsWgDevice(), nil
}

// AsWgDevice creates a view of the current tunnel state as a wireguard wgtypes.Device
func (t *Tunnel) AsWgDevice() *wgtypes.Device {
	t.m.Lock()
	defer t.m.Unlock()

	ret := &wgtypes.Device{
		Name:       t.name,
		ListenPort: -1,
		Type:       wgtypes.Unknown, // this is not a real device
		PrivateKey: t.privateKey,
		PublicKey:  t.publicKey,
	}
	if t.upstream != nil {
		ret.ListenPort = t.upstream.addr.Port
	}

	for _, p := range t.peers {
		peer := wgtypes.Peer{
			PublicKey:         p.publicKey,
			Endpoint:          util.CloneUDPAddr(p.endpoint),
			AllowedIPs:        nil, // below
			LastHandshakeTime: p.lastReceive,
		}
		for _, addr := range p.addrs {
			peer.AllowedIPs = append(peer.AllowedIPs, util.CloneIPNet(addr))
		}
		ret.Peers = append(ret.Peers, peer)
	}

	return ret
}

func (hc *hostWgClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if cfg.FirewallMark != nil || cfg.ListenPort != nil || cfg.PrivateKey != nil {
		return errors.New("Not allowed to reconfigure core tunnel settings")
	}

	i := hc.h.Interface(name)
	t, ok := i.(*Tunnel)
	if !ok {
		return errors.Errorf("Interface %s is not a tunnel", name)
	}

	if cfg.ReplacePeers {
		t.m.Lock()
		t.peers = map[string]*TunPeer{}
		t.m.Unlock()
	}

	for _, p := range cfg.Peers {
		if p.PersistentKeepaliveInterval != nil || p.PresharedKey != nil {
			return errors.New("Advanced peer features not supported")
		}
		peerID := p.PublicKey.String()
		t.m.Lock()
		tp := t.peers[peerID]
		t.m.Unlock()
		if tp == nil {
			if p.Remove {
				continue
			} else if p.UpdateOnly {
				continue
			} else {
				/* tp = */ t.AddPeer(peerID, p.PublicKey, p.Endpoint, p.AllowedIPs)
			}
		} else if p.Remove {
			t.DelPeer(peerID)
		} else {
			t.m.Lock()
			if p.Endpoint != nil {
				tp.endpoint = util.CloneUDPAddr(p.Endpoint)
			}
			if p.ReplaceAllowedIPs {
				tp.addrs = map[string]net.IPNet{}
			}
			for _, a := range p.AllowedIPs {
				tp.addrs[a.String()] = a
			}
			t.m.Unlock()
		}
	}

	return nil
}
