package config

import (
	"fmt"

	"github.com/fastcat/wirelink/trust"
)

// Peer represents the parsed info about a peer read from the config file
type Peer struct {
	Name          string
	Trust         *trust.Level
	FactExchanger bool
	Endpoints     []string
	Basic         bool
}

func (p *Peer) String() string {
	trustStr := "nil"
	if p.Trust != nil {
		trustStr = p.Trust.String()
	}
	return fmt.Sprintf("{Name:%s Trust:%s Exch:%v EPs:%d B:%t}",
		p.Name, trustStr, p.FactExchanger, len(p.Endpoints), p.Basic)
}
