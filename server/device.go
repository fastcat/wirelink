package server

import (
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/peerfacts"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// deviceState does a mutex-protected access to read the current state of the
// wireguard device
func (s *LinkServer) deviceState() (dev *wgtypes.Device, err error) {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	return s.ctrl.Device(s.config.Iface)
}

func (s *LinkServer) collectFacts(dev *wgtypes.Device) (ret []*fact.Fact, err error) {
	pf, err := peerfacts.DeviceFacts(dev, FactTTL)
	if err != nil {
		return
	}
	ret = make([]*fact.Fact, len(pf))
	copy(ret, pf)
	for _, peer := range dev.Peers {
		pf, err = peerfacts.LocalFacts(&peer, FactTTL)
		if err != nil {
			return
		}
		ret = append(ret, pf...)
	}
	return
}
