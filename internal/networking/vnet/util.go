package vnet

import "net"

func subnetMatch(ip net.IP, addrs map[string]net.IPNet) bool {
	for _, a := range addrs {
		am := a.IP.Mask(a.Mask)
		pm := ip.Mask(a.Mask)
		if am.Equal(pm) {
			return true
		}
	}
	return false
}

func destinationAddrMatch(p *Packet, addrs map[string]net.IPNet) bool {
	ip := p.dest.IP
	for _, a := range addrs {
		if ip.Equal(a.IP) {
			return true
		}
	}
	return false
}

func destinationSubnetMatch(p *Packet, addrs map[string]net.IPNet) bool {
	return subnetMatch(p.dest.IP, addrs)
}

func sourceSubnetMatch(p *Packet, addrs map[string]net.IPNet) bool {
	return subnetMatch(p.src.IP, addrs)
}

func destinationSocket(p *Packet, sockets map[string]*Socket) *Socket {
	for _, s := range sockets {
		if s.addr.Port != p.dest.Port {
			continue
		}
		if s.addr.IP.Equal(net.IPv4zero) || s.addr.IP.Equal(net.IPv6zero) || s.addr.IP.Equal(p.dest.IP) {
			// TODO: differentiate v4 and v6 any addresses here
			return s
		}
	}
	return nil
}

func cloneBytes(p []byte) []byte {
	if p == nil {
		return nil
	}
	r := make([]byte, len(p))
	copy(r, p)
	return r
}
