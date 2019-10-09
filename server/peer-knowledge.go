package server

import (
	"sync"
	"time"

	"github.com/fastcat/wirelink/fact"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerKnowledgeKey struct {
	fact.Key
	peer wgtypes.Key
}

type peerKnowledgeSet struct {
	// data maps a PKK (fact key + source peer) to its expiration time for that peer
	data   map[peerKnowledgeKey]time.Time
	access *sync.RWMutex
}

func newPKS() *peerKnowledgeSet {
	return &peerKnowledgeSet{
		data:   make(map[peerKnowledgeKey]time.Time),
		access: new(sync.RWMutex),
	}
}

func (pks *peerKnowledgeSet) upsertReceived(rf *ReceivedFact, pl peerLookup) bool {
	peer, ok := pl.get(rf.source)
	if !ok {
		return false
	}
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(rf.fact),
		peer: peer,
	}
	pks.access.Lock()
	defer pks.access.Unlock()
	t, ok := pks.data[k]
	if !ok || rf.fact.Expires.After(t) {
		pks.data[k] = rf.fact.Expires
		return true
	}
	return false
}

func (pks *peerKnowledgeSet) upsertSent(peer *wgtypes.Peer, f *fact.Fact) bool {
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer.PublicKey,
	}
	pks.access.Lock()
	defer pks.access.Unlock()
	t, ok := pks.data[k]
	if !ok || f.Expires.After(t) {
		pks.data[k] = f.Expires
		return true
	}
	return false
}

func (pks peerKnowledgeSet) expire() (ret int) {
	now := time.Now()
	pks.access.Lock()
	defer pks.access.Unlock()
	for key, value := range pks.data {
		if now.After(value) {
			delete(pks.data, key)
			ret++
		}
	}
	return
}

func (pks peerKnowledgeSet) peerKnows(peer *wgtypes.Peer, f *fact.Fact, hysteresis time.Duration) bool {
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer.PublicKey,
	}
	pks.access.RLock()
	defer pks.access.RUnlock()
	e, ok := pks.data[k]
	// peer knows a fact if it knows it at all, and if its expiration time for the fact is
	// after the fact's expiration, or no more than hysteresis behind it
	return ok && e.Add(hysteresis).After(f.Expires)
}

func (pks peerKnowledgeSet) peerNeeds(peer *wgtypes.Peer, f *fact.Fact, maxTTL time.Duration) bool {
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer.PublicKey,
	}
	pks.access.RLock()
	defer pks.access.RUnlock()
	e, ok := pks.data[k]
	// peer needs a fact if it doesnt know it at all,
	// or if it's going to forget it within maxTTL and we have something fresher
	return !ok || time.Now().Add(maxTTL).After(e) && e.Before(f.Expires)
}

func (pks peerKnowledgeSet) peerAlive(peer *wgtypes.Peer, maxTTL time.Duration) bool {
	k := peerKnowledgeKey{
		Key: fact.KeyOf(&fact.Fact{
			Attribute: fact.AttributeUnknown,
			Subject:   &fact.PeerSubject{Key: peer.PublicKey},
			Value:     fact.EmptyValue{},
		}),
		peer: peer.PublicKey,
	}
	pks.access.RLock()
	defer pks.access.RUnlock()
	e, ok := pks.data[k]
	// a peer is alive if it has sent us a null fact that is not going to expire within maxTTL
	return ok && time.Now().Add(maxTTL).Before(e)
}
