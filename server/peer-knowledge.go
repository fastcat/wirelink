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

// peerKnows returns that a peer knows a fact if we think it knows it (not pruned by `expire`),
// and its expiration is no more than hysteresis behind the local fact (or later than it)
func (pks peerKnowledgeSet) peerKnows(peer *wgtypes.Peer, f *fact.Fact, hysteresis time.Duration) bool {
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer.PublicKey,
	}
	pks.access.RLock()
	defer pks.access.RUnlock()
	e, ok := pks.data[k]
	return ok && e.Add(hysteresis).After(f.Expires)
}

// peerNeeds returns that a peer needs a fact if it either doesn't know it at all,
// or if it is going to forget it within maxTTL and the local fact will expire later
func (pks peerKnowledgeSet) peerNeeds(peer *wgtypes.Peer, f *fact.Fact, maxTTL time.Duration) bool {
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer.PublicKey,
	}
	pks.access.RLock()
	defer pks.access.RUnlock()
	e, ok := pks.data[k]
	return !ok || time.Now().Add(maxTTL).After(e) && e.Before(f.Expires)
}

// peerAlive returns if we have received an alive fact from the peer which is going to be alive
// for at least `maxTTL`. Commonly `maxTTL` will be set to zero.
func (pks peerKnowledgeSet) peerAlive(peer wgtypes.Key, maxTTL time.Duration) bool {
	k := peerKnowledgeKey{
		Key: fact.KeyOf(&fact.Fact{
			Attribute: fact.AttributeUnknown,
			Subject:   &fact.PeerSubject{Key: peer},
			Value:     fact.EmptyValue{},
		}),
		peer: peer,
	}
	pks.access.RLock()
	defer pks.access.RUnlock()
	e, ok := pks.data[k]
	// a peer is alive if it has sent us a null fact that is not going to expire within maxTTL
	return ok && time.Now().Add(maxTTL).Before(e)
}
