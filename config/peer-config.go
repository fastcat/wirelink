package config

import (
	"fmt"
	"net"

	"github.com/fastcat/wirelink/trust"
)

// PeerEndpoint represents a single endpoint (possibly by hostname) for a peer
type PeerEndpoint struct {
	// Host may be either an IP or a hostname
	Host string
	Port int
}

// Peer represents the parsed info about a peer read from the config file
type Peer struct {
	Name          string
	Trust         *trust.Level
	FactExchanger bool
	Endpoints     []PeerEndpoint
	AllowedIPs    []net.IPNet
	Basic         bool
}

func (p *Peer) String() string {
	trustStr := "nil"
	if p.Trust != nil {
		trustStr = p.Trust.String()
	}
	return fmt.Sprintf("{Name:%s Trust:%s Exch:%v EPs:%d AIPs:%d B:%t}",
		p.Name, trustStr, p.FactExchanger, len(p.Endpoints), len(p.AllowedIPs), p.Basic)
}
