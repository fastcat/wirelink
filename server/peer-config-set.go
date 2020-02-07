package server

import (
	"sync"

	"github.com/fastcat/wirelink/apply"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerConfigSet struct {
	peerStates map[wgtypes.Key]*apply.PeerConfigState
	psm        *sync.Mutex
}

func newPeerConfigSet() *peerConfigSet {
	return &peerConfigSet{
		peerStates: make(map[wgtypes.Key]*apply.PeerConfigState),
		psm:        new(sync.Mutex),
	}
}

func (pcs *peerConfigSet) Trim(keep func(key wgtypes.Key) bool) {
	pcs.psm.Lock()
	defer pcs.psm.Unlock()
	for k := range pcs.peerStates {
		if !keep(k) {
			delete(pcs.peerStates, k)
		}
	}
}

func (pcs *peerConfigSet) Get(key wgtypes.Key) (ret *apply.PeerConfigState, ok bool) {
	pcs.psm.Lock()
	ret, ok = pcs.peerStates[key]
	pcs.psm.Unlock()
	return
}

func (pcs *peerConfigSet) Set(key wgtypes.Key, value *apply.PeerConfigState) {
	pcs.psm.Lock()
	pcs.peerStates[key] = value
	pcs.psm.Unlock()
}

func (pcs *peerConfigSet) ForEach(visitor func(key wgtypes.Key, value *apply.PeerConfigState)) {
	pcs.psm.Lock()
	defer pcs.psm.Unlock()
	for k, v := range pcs.peerStates {
		visitor(k, v)
	}
}

// Clone makes a deep clone of the receiver
func (pcs *peerConfigSet) Clone() *peerConfigSet {
	if pcs == nil {
		return nil
	}

	pcs.psm.Lock()
	defer pcs.psm.Unlock()

	ret := &peerConfigSet{
		peerStates: make(map[wgtypes.Key]*apply.PeerConfigState),
		psm:        &sync.Mutex{},
	}
	for k, v := range pcs.peerStates {
		ret.peerStates[k] = v.Clone()
	}
	return ret
}
