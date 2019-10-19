package config

import (
	"github.com/fastcat/wirelink/trust"
)

// Peer represents the parsed info about a peer read from the config file
type Peer struct {
	Name  string
	Trust *trust.Level
}
