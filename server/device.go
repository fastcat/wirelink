package server

import (
	"path/filepath"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"
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

func (s *LinkServer) shouldReportIface(name string) bool {
	// MUST NOT match any excludes
	for _, glob := range s.config.HideIfaces {
		if matched, err := filepath.Match(glob, name); matched && err == nil {
			log.Debug("Hiding iface '%s' because it matches exclude '%s'\n", name, glob)
			return false
		}
	}
	if len(s.config.ReportIfaces) == 0 {
		log.Debug("Including iface '%s' because no includes are configured", name)
		return true
	}
	// if any includes are specified, name MUST match one of them
	for _, glob := range s.config.ReportIfaces {
		if matched, err := filepath.Match(glob, name); matched && err == nil {
			log.Debug("Including iface '%s' because it matches include '%s'\n", name, glob)
			return true
		}
	}
	log.Debug("Hiding iface '%s' because it doesn't match any includes\n", name)
	return false
}

func (s *LinkServer) collectFacts(dev *wgtypes.Device) (ret []*fact.Fact, err error) {
	pf, err := peerfacts.DeviceFacts(dev, FactTTL, s.shouldReportIface)
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
