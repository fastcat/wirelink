package server

import (
	"time"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
