package server

import (
	"net"
	"sync"

	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/log"
)

type interfaceCache struct {
	mu sync.RWMutex

	env   networking.Environment
	iface string

	// IPNets assigned to the tunnel
	tunnelIPNets []net.IPNet
	// IPNets for local network interfaces other than the tunnel
	hostIPNets []net.IPNet

	dirty bool
}

func newInterfaceCache(env networking.Environment, iface string) (*interfaceCache, error) {
	cache := &interfaceCache{
		env:   env,
		iface: iface,
	}
	if err := cache.read(); err != nil {
		return nil, err
	}
	return cache, nil
}

func (ic *interfaceCache) read() error {
	ifaces, err := ic.env.Interfaces()
	if err != nil {
		log.Error("unable to load network interfaces: %v", err)
		// don't abort the caller, continue with whatever info we have from last time
		return err
	}
	ic.tunnelIPNets = ic.tunnelIPNets[:0]
	ic.hostIPNets = ic.hostIPNets[:0]
	for _, iface := range ifaces {
		if addrs, err := iface.Addrs(); err != nil {
			log.Error("unable to fetch addresses from %s: %v", iface.Name(), err)
		} else if iface.Name() == ic.iface {
			ic.tunnelIPNets = append(ic.tunnelIPNets, addrs...)
		} else {
			ic.hostIPNets = append(ic.hostIPNets, addrs...)
		}
	}
	return nil
}

// Dirty marks the cached data dirty, so the next query will force a refresh.
func (ic *interfaceCache) Dirty() {
	ic.mu.Lock()
	ic.dirty = true
	ic.mu.Unlock()
}

// WillTunnel heuristically checks if an IP is likely to route via the tunnel.
// An IP that matches a non-tunnel interface subnet is expected not to tunnel.
// An IP that doesn't match those but does match a tunnel subnet is expected to
// tunnel. Any other IP is expected to not tunnel.
func (ic *interfaceCache) WillTunnel(ip net.IP) bool {
	ic.mu.RLock()
	if ic.dirty {
		ic.mu.RUnlock()
		ic.mu.Lock()
		_ = ic.read()
		ic.mu.Unlock()
		ic.mu.RLock()
	}

	isTunnel := false
	for _, ipn := range ic.tunnelIPNets {
		if ipn.Contains(ip) {
			isTunnel = true
			break
		}
	}
	if !isTunnel {
		ic.mu.RUnlock()
		return false
	}
	for _, ipn := range ic.hostIPNets {
		if ipn.Contains(ip) {
			isTunnel = false
			break
		}
	}

	ic.mu.RUnlock()
	return isTunnel
}
