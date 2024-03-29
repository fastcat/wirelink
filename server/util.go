package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/detect"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (s *LinkServer) peerConfigName(peer wgtypes.Key) string {
	return s.config.Peers.Name(peer)
}

func (s *LinkServer) peerName(peer wgtypes.Key) string {
	ret := s.peerConfigName(peer)
	if len(ret) > 0 {
		return ret
	}
	pcs, _ := s.peerConfig.Get(peer)
	ret, _ = pcs.TryGetMetadata(fact.MemberName)
	if len(ret) > 0 {
		return ret
	}
	// TODO: don't rely on signer for this
	if peer == s.signer.PublicKey {
		return "self"
	}
	return peer.String()
}

// peerNamer is meant to be passed as the subjectFormatter to Fact.FancyString
// or FactKey.FancyString.
func (s *LinkServer) peerNamer(fs fact.Subject) string {
	if ps, ok := fs.(*fact.PeerSubject); ok {
		return s.peerName(ps.Key)
	}
	return fs.String()
}

func (s *LinkServer) formatFacts(
	now time.Time,
	facts []*fact.Fact,
) string {
	// print facts out in a consistent ordering
	facts = fact.SortedCopy(facts)
	var str strings.Builder
	str.WriteString("Current facts:")
	// protect against tests mutating config while we read it
	for _, fact := range facts {
		str.WriteRune('\n')
		str.WriteString(fact.FancyString(s.peerNamer, now))
	}
	str.WriteString("\nCurrent peers:")
	s.peerConfig.ForEach(func(k wgtypes.Key, pcs *apply.PeerConfigState) {
		// local device will generally be in this list, but we don't want to list it
		// TODO: don't rely on signer for this
		if k == s.signer.PublicKey {
			return
		}
		peerName := s.peerConfigName(k)
		if len(peerName) == 0 {
			peerName, _ = pcs.TryGetMetadata(fact.MemberName)
			if len(peerName) == 0 {
				peerName = k.String()
			}
		}
		fmt.Fprintf(&str, "\nPeer %s is %s", peerName, pcs.Describe(now))
	})
	str.WriteString("\nSelf: ")
	str.WriteString(s.Describe())
	return str.String()
}

// groupFactsByPeer takes a list of facts and groups them by the public key in
// their Subject. Any facts that don't have a PeerSubject will be logged as an error,
// but otherwise ignored.
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
func (s *LinkServer) UpdateRouterState(dev *wgtypes.Device, logChanges bool) {
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
}
