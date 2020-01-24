package server

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/detect"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (s *LinkServer) peerName(peer wgtypes.Key) string {
	return s.config.Peers.Name(peer)
}

func (s *LinkServer) printFactsIfRequested(
	dev *wgtypes.Device,
	facts []*fact.Fact,
) {
	printsRequested := atomic.LoadInt32(s.printsRequested)
	if printsRequested == 0 {
		return
	}
	defer atomic.CompareAndSwapInt32(s.printsRequested, printsRequested, 0)

	// not safe safe to mutate the shared facts we received
	facts = fact.SortedCopy(facts)
	var str strings.Builder
	str.WriteString("Current facts:")
	peerNamer := func(fs fact.Subject) string {
		if ps, ok := fs.(*fact.PeerSubject); ok {
			return s.peerName(ps.Key)
		}
		return fs.String()
	}
	for _, fact := range facts {
		str.WriteRune('\n')
		str.WriteString(fact.FancyString(peerNamer))
	}
	str.WriteString("\nCurrent peers:")
	s.peerConfig.ForEach(func(k wgtypes.Key, pcs *apply.PeerConfigState) {
		fmt.Fprintf(&str, "\nPeer %s is %s", s.peerName(k), pcs.Describe())
	})
	str.WriteString("\nSelf: ")
	str.WriteString(s.Describe())
	log.Info("%s", str.String())
}

func groupFactsByPeer(facts []*fact.Fact) map[wgtypes.Key][]*fact.Fact {
	factsByPeer := make(map[wgtypes.Key][]*fact.Fact)
	for _, f := range facts {
		ps, ok := f.Subject.(*fact.PeerSubject)
		if !ok {
			// WAT
			log.Error("WAT: fact subject is a %T: %v", f.Subject, f)
			continue
		}
		factsByPeer[ps.Key] = append(factsByPeer[ps.Key], f)
	}
	return factsByPeer
}

// UpdateRouterState will update `s.config.IsRouterNow` based on the device state,
// if `s.config.AutoDetectRouter` is true.
// The possible error return is for future use cases, it always returns `nil` for now
func (s *LinkServer) UpdateRouterState(dev *wgtypes.Device, logChanges bool) error {
	if s.config.AutoDetectRouter {
		newValue := detect.IsDeviceRouter(dev)
		if newValue != s.config.IsRouterNow {
			if logChanges {
				newState := "leaf"
				if newValue {
					newState = "router"
				}
				log.Info("Detected we are now a %s", newState)
			}
			s.config.IsRouterNow = newValue
		}
	}

	return nil
}
