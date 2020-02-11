package server

import (
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils/facts"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// mockPeerAlive updates the peerKnowledgeSet to know that the given peer is alive
func (pks *peerKnowledgeSet) mockPeerAlive(peer wgtypes.Key, expires time.Time, bootID *uuid.UUID) *peerKnowledgeSet {
	pks.access.Lock()
	defer pks.access.Unlock()

	k := aliveKey(peer)
	pks.data[k] = expires
	if bootID != nil {
		pks.bootIDs[peer] = *bootID
	} else if pks.bootIDs[peer] == (uuid.UUID{}) {
		pks.bootIDs[peer] = uuid.Must(uuid.NewRandom())
	}

	return pks
}

// mockPeerKnows updates the peerKnowledgeSet to know that the given peer knows the given fact
func (pks *peerKnowledgeSet) mockPeerKnows(peer *wgtypes.Key, f *fact.Fact) *peerKnowledgeSet {
	pks.upsertSent(&wgtypes.Peer{PublicKey: *peer}, f)
	return pks
}

// mockPeerKnowsLocalAlive updates the peerKnowledgeSet to know that the given peer knows the local system is alive
func (pks *peerKnowledgeSet) mockPeerKnowsLocalAlive(remote, local *wgtypes.Key, expires time.Time, bootID *uuid.UUID) *peerKnowledgeSet {
	return pks.mockPeerKnows(remote, facts.AliveFactFull(local, expires, *bootID))
}
