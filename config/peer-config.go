package config

import (
	"github.com/fastcat/wirelink/trust"
	"github.com/pkg/errors"
)

// Peer represents the info about a peer read from the config file
type Peer struct {
	Name  string
	Trust string
}

// TrustLevel parses the Trust string to a trust.Level
func (p *Peer) TrustLevel() (trust.Level, error) {
	val, ok := trust.Names[p.Trust]
	if !ok {
		return trust.Untrusted, errors.Errorf("Invalid trust level '%s'", p.Trust)
	}
	return val, nil
}

// Validate checks that the object is valid
func (p *Peer) Validate() error {
	_, err := p.TrustLevel()
	if err != nil {
		return err
	}
	return nil
}
