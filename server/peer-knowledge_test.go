package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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

func Test_peerKnowledgeSet_upsertReceived(t *testing.T) {
	now := time.Now()
	oldExpires := now.Add(FactTTL / 2)
	expires := now.Add(FactTTL)

	k1 := testutils.MustKey(t)
	k1source := net.UDPAddr{IP: autopeer.AutoAddress(k1)}
	ep1 := testutils.RandUDP4Addr(t)
	uuid1 := uuid.Must(uuid.NewRandom())
	uuid2 := uuid.Must(uuid.NewRandom())

	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
	}
	type args struct {
		rf *ReceivedFact
		pl peerLookup
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       bool
		wantFields fields
	}{
		{
			"simple new fact",
			fields{
				map[peerKnowledgeKey]time.Time{},
				map[wgtypes.Key]uuid.UUID{},
			},
			args{
				&ReceivedFact{
					fact:   facts.EndpointFactFull(ep1, &k1, expires),
					source: k1source,
				},
				createFromKeys(k1),
			},
			true,
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.EndpointFactFull(ep1, &k1, expires), k1): expires,
				},
				map[wgtypes.Key]uuid.UUID{},
			},
		},
		{
			"simple old fact",
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.EndpointFactFull(ep1, &k1, expires), k1): expires,
				},
				map[wgtypes.Key]uuid.UUID{},
			},
			args{
				&ReceivedFact{
					fact:   facts.EndpointFactFull(ep1, &k1, oldExpires),
					source: k1source,
				},
				createFromKeys(k1),
			},
			false,
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.EndpointFactFull(ep1, &k1, expires), k1): expires,
				},
				map[wgtypes.Key]uuid.UUID{},
			},
		},
		{
			"peer reboot",
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.EndpointFactFull(ep1, &k1, expires), k1): expires,
				},
				map[wgtypes.Key]uuid.UUID{
					k1: uuid1,
				},
			},
			args{
				&ReceivedFact{
					fact:   facts.AliveFactFull(&k1, expires, uuid2),
					source: k1source,
				},
				createFromKeys(k1),
			},
			true,
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.AliveFactFull(&k1, expires, uuid2), k1): expires,
				},
				map[wgtypes.Key]uuid.UUID{
					k1: uuid2,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  &sync.RWMutex{},
			}
			assert.Equal(t, tt.want, pks.upsertReceived(tt.args.rf, tt.args.pl))
			assert.Equal(t, tt.wantFields.data, pks.data)
			assert.Equal(t, tt.wantFields.bootIDs, pks.bootIDs)
		})
	}
}

func Test_peerKnowledgeSet_upsertSent(t *testing.T) {
	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
	}
	type args struct {
		peer *wgtypes.Peer
		f    *fact.Fact
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       bool
		wantFields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  &sync.RWMutex{},
			}
			assert.Equal(t, tt.want, pks.upsertSent(tt.args.peer, tt.args.f))
			assert.Equal(t, tt.wantFields.data, pks.data)
			assert.Equal(t, tt.wantFields.bootIDs, pks.bootIDs)
		})
	}
}

func Test_peerKnowledgeSet_expire(t *testing.T) {
	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
	}
	tests := []struct {
		name       string
		fields     fields
		wantCount  int
		wantFields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  &sync.RWMutex{},
			}
			assert.Equal(t, tt.wantCount, pks.expire())
			assert.Equal(t, tt.wantFields.data, pks.data)
			assert.Equal(t, tt.wantFields.bootIDs, pks.bootIDs)
		})
	}
}

func Test_peerKnowledgeSet_peerKnows(t *testing.T) {
	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
	}
	type args struct {
		peer       *wgtypes.Peer
		f          *fact.Fact
		hysteresis time.Duration
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  &sync.RWMutex{},
			}
			assert.Equal(t, tt.want, pks.peerKnows(tt.args.peer, tt.args.f, tt.args.hysteresis))
		})
	}
}

func Test_peerKnowledgeSet_peerNeeds(t *testing.T) {
	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
	}
	type args struct {
		peer   *wgtypes.Peer
		f      *fact.Fact
		maxTTL time.Duration
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  &sync.RWMutex{},
			}
			assert.Equal(t, tt.want, pks.peerNeeds(tt.args.peer, tt.args.f, tt.args.maxTTL))
		})
	}
}

func Test_peerKnowledgeSet_peerAlive(t *testing.T) {
	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
		access  *sync.RWMutex
	}
	type args struct {
		peer   wgtypes.Key
		maxTTL time.Duration
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantAlive  bool
		wantBootID *uuid.UUID
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  tt.fields.access,
			}
			gotAlive, gotBootID := pks.peerAlive(tt.args.peer, tt.args.maxTTL)
			assert.Equal(t, tt.wantAlive, gotAlive)
			assert.Equal(t, tt.wantBootID, gotBootID)
		})
	}
}

func Test_peerKnowledgeSet_forcePing(t *testing.T) {
	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
	}
	type args struct {
		self wgtypes.Key
		peer wgtypes.Key
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantFields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  &sync.RWMutex{},
			}
			pks.forcePing(tt.args.self, tt.args.peer)
			assert.Equal(t, tt.wantFields.data, pks.data)
			assert.Equal(t, tt.wantFields.bootIDs, pks.bootIDs)
		})
	}
}

func Test_peerKnowledgeSet_peerBootID(t *testing.T) {
	type fields struct {
		data    map[peerKnowledgeKey]time.Time
		bootIDs map[wgtypes.Key]uuid.UUID
	}
	type args struct {
		peer wgtypes.Key
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *uuid.UUID
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				access:  &sync.RWMutex{},
			}
			assert.Equal(t, tt.want, pks.peerBootID(tt.args.peer))
		})
	}
}
