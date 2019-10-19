package config

import (
	"github.com/fastcat/wirelink/trust"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerData represents the raw data to configure a peer read from the config file
type PeerData struct {
	PublicKey string
	Name      string
	Trust     string
}

// Parse validates the info in the PeerData and returns the parsed tuple + error
func (p *PeerData) Parse() (key wgtypes.Key, peer Peer, err error) {
	if p.Trust != "" {
		val, ok := trust.Names[p.Trust]
		if !ok {
			err = errors.Errorf("Invalid trust level '%s'", p.Trust)
			return
		}
		peer.Trust = &val
	}
	peer.Name = p.Name
	if key, err = wgtypes.ParseKey(p.PublicKey); err != nil {
		return
	}
	return
}
