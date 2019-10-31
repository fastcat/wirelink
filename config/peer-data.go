package config

import (
	"net"

	"github.com/fastcat/wirelink/trust"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerData represents the raw data to configure a peer read from the config file
type PeerData struct {
	PublicKey     string
	Name          string
	Trust         string
	FactExchanger bool
	Endpoints     []string
}

// Parse validates the info in the PeerData and returns the parsed tuple + error
func (p *PeerData) Parse() (key wgtypes.Key, peer Peer, err error) {
	if key, err = wgtypes.ParseKey(p.PublicKey); err != nil {
		return
	}
	peer.Name = p.Name
	if p.Trust != "" {
		val, ok := trust.Values[p.Trust]
		if !ok {
			err = errors.Errorf("Invalid trust level '%s'", p.Trust)
			return
		}
		peer.Trust = &val
	}
	peer.FactExchanger = p.FactExchanger
	// we don't do the DNS resolution here because we want it to refresh
	// periodically, esp. if we move across a split horizon boundary
	// we do want to validate the host/port split however
	for _, ep := range p.Endpoints {
		if _, _, err = net.SplitHostPort(ep); err != nil {
			err = errors.Wrapf(err, "Bad endpoint '%s' for '%s'='%s'", ep, p.PublicKey, p.Name)
			return
		}
		//TODO: can validate host portion is syntactically valid: do a lookup and
		// ignore host not found errors
		//TODO: can validate port here
	}
	peer.Endpoints = p.Endpoints
	return
}
