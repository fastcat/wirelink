package server

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerKnowledgeKey struct {
	fact.Key
	peer wgtypes.Key
}

func keyOf(f *fact.Fact, peer wgtypes.Key) peerKnowledgeKey {
	return peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer,
	}
}

type peerKnowledgeSet struct {
	// data maps a PKK (fact key + source peer) to its expiration time for that peer
	data    map[peerKnowledgeKey]time.Time
	bootIDs map[wgtypes.Key]uuid.UUID
	access  *sync.RWMutex
}

func newPKS() *peerKnowledgeSet {
	return &peerKnowledgeSet{
		data:    make(map[peerKnowledgeKey]time.Time),
		bootIDs: make(map[wgtypes.Key]uuid.UUID),
		access:  new(sync.RWMutex),
	}
}

// upsertReceived records a newly received fact, noting that the peer that sent it
// to us knows it (if the source is valid for a peer in the lookup), returning
// true if we recorded new information, or false if the source was invalid or
// the info was otherwise rejected (e.g. an older expiration than what we already
// knew the peer knows).
func (pks *peerKnowledgeSet) upsertReceived(rf *ReceivedFact, pl peerLookup) bool {
	peer, ok := pl.get(rf.source.IP)
	if !ok {
		return false
	}
	k := keyOf(rf.fact, peer)

	pks.access.Lock()
	defer pks.access.Unlock()

	// alive facts need special handling to understand that the peer has "forgotten" everything
	// if its boot id changes
	if rf.fact.Attribute == fact.AttributeAlive {
		oldID, oldIDOk := pks.bootIDs[k.peer]
		uv, uvOk := rf.fact.Value.(*fact.UUIDValue)
		// we prune on the first receive in addition to any changes,
		// since it likely didn't hear things we sent before
		// note that this is intentionally different from how the alive logging elsewhere works
		if !oldIDOk || !uvOk || oldID != uv.UUID {
			// TODO: use peername here
			log.Debug("Detected bootID change from %v, pruning knowledge", k.peer)
			// boot id changed, prune everything we think this peer knows
			for dk := range pks.data {
				if dk.peer == k.peer {
					delete(pks.data, dk)
				}
			}
		}
		if uvOk {
			pks.bootIDs[k.peer] = uv.UUID
		}
	}
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

func (pks *peerKnowledgeSet) expire() (count int) {
	now := time.Now()
	pks.access.Lock()
	defer pks.access.Unlock()
	for key, value := range pks.data {
		if now.After(value) {
			delete(pks.data, key)
			count++
		}
	}
	return
}

// peerKnows returns that a peer knows a fact if we think it knows it (not pruned by `expire`),
// and its expiration is no more than hysteresis behind the local fact (or later than it)
func (pks *peerKnowledgeSet) peerKnows(peer *wgtypes.Peer, f *fact.Fact, hysteresis time.Duration) bool {
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer.PublicKey,
	}
	pks.access.RLock()
	e, ok := pks.data[k]
	pks.access.RUnlock()
	return ok && !e.Add(hysteresis).Before(f.Expires)
}

// peerNeeds returns that a peer needs a fact if it either doesn't know it at all,
// or if it is going to forget it within maxTTL and the local fact will expire later
func (pks *peerKnowledgeSet) peerNeeds(peer *wgtypes.Peer, f *fact.Fact, maxTTL time.Duration) bool {
	k := peerKnowledgeKey{
		Key:  fact.KeyOf(f),
		peer: peer.PublicKey,
	}
	pks.access.RLock()
	e, ok := pks.data[k]
	pks.access.RUnlock()
	return !ok || time.Now().Add(maxTTL).After(e) && e.Before(f.Expires)
}

func aliveKey(peer wgtypes.Key) peerKnowledgeKey {
	return peerKnowledgeKey{
		Key: fact.KeyOf(&fact.Fact{
			Attribute: fact.AttributeAlive,
			Subject:   &fact.PeerSubject{Key: peer},
			// value doesn't actually matter for alive packet keying
			Value: &fact.EmptyValue{},
		}),
		peer: peer,
	}
}

// peerAlive returns if we have received an alive fact from the peer which is going to be alive
// for at least `maxTTL`. Commonly `maxTTL` will be set to zero.
func (pks *peerKnowledgeSet) peerAlive(peer wgtypes.Key, maxTTL time.Duration) (alive bool, bootID *uuid.UUID) {
	k := aliveKey(peer)
	pks.access.RLock()
	e, eok := pks.data[k]
	id, idOk := pks.bootIDs[peer]
	pks.access.RUnlock()
	idRet := &id
	if !idOk {
		idRet = nil
	}
	// a peer is alive if it has sent us a null fact that is not going to expire within maxTTL
	return eok && time.Now().Add(maxTTL).Before(e), idRet
}

// forcePing forgets that we have sent a ping to the peer, forcing it to be re-sent
// on the next check.
func (pks *peerKnowledgeSet) forcePing(self, peer wgtypes.Key) {
	k := peerKnowledgeKey{
		Key: fact.KeyOf(&fact.Fact{
			Attribute: fact.AttributeAlive,
			Subject:   &fact.PeerSubject{Key: self},
			// value doesn't actually matter for alive packet keying
			Value: &fact.EmptyValue{},
		}),
		peer: peer,
	}
	pks.access.Lock()
	delete(pks.data, k)
	pks.access.Unlock()
}

func (pks *peerKnowledgeSet) peerBootID(peer wgtypes.Key) *uuid.UUID {
	pks.access.RLock()
	id, ok := pks.bootIDs[peer]
	pks.access.RUnlock()
	if ok {
		return &id
	}
	return nil
}
