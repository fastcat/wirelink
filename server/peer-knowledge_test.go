package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
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
	pks.sent(&wgtypes.Peer{PublicKey: *peer}, f)
	return pks
}

// mockPeerKnowsLocalAlive updates the peerKnowledgeSet to know that the given peer knows the local system is alive
func (pks *peerKnowledgeSet) mockPeerKnowsLocalAlive(remote, local *wgtypes.Key, expires time.Time, bootID *uuid.UUID) *peerKnowledgeSet {
	return pks.mockPeerKnows(remote, facts.AliveFactFull(local, expires, *bootID))
}

func Test_peerKnowledgeSet_received(t *testing.T) {
	now := time.Now()
	oldExpires := now.Add(DefaultFactTTL / 2)
	expires := now.Add(DefaultFactTTL)

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
		rf   *ReceivedFact
		keys []wgtypes.Key
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
				[]wgtypes.Key{k1},
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
				[]wgtypes.Key{k1},
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
				[]wgtypes.Key{k1},
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
			pl := newPeerLookup()
			pl.addKeys(tt.args.keys...)
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
				pl:      pl,
			}
			assert.Equal(t, tt.want, pks.received(tt.args.rf))
			assert.Equal(t, tt.wantFields.data, pks.data)
			assert.Equal(t, tt.wantFields.bootIDs, pks.bootIDs)
		})
	}
}

func Test_peerKnowledgeSet_sent(t *testing.T) {
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
			}
			assert.Equal(t, tt.want, pks.sent(tt.args.peer, tt.args.f))
			assert.Equal(t, tt.wantFields.data, pks.data)
			assert.Equal(t, tt.wantFields.bootIDs, pks.bootIDs)
		})
	}
}

func Test_peerKnowledgeSet_expire(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)
	expired := now.Add(-time.Millisecond)
	k1 := testutils.MustKey(t)
	ep1 := testutils.RandUDP4Addr(t)

	type fields struct {
		data map[peerKnowledgeKey]time.Time
	}
	tests := []struct {
		name       string
		fields     fields
		wantCount  int
		wantFields fields
	}{
		{
			"empty",
			fields{
				map[peerKnowledgeKey]time.Time{},
			},
			0,
			fields{
				map[peerKnowledgeKey]time.Time{},
			},
		},
		{
			"nothing expired",
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.EndpointFactFull(ep1, &k1, expires), k1): expires,
				},
			},
			0,
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.EndpointFactFull(ep1, &k1, expires), k1): expires,
				},
			},
		},
		{
			"one thing expired",
			fields{
				map[peerKnowledgeKey]time.Time{
					keyOf(facts.EndpointFactFull(ep1, &k1, expired), k1): expired,
				},
			},
			1,
			fields{
				map[peerKnowledgeKey]time.Time{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data: tt.fields.data,
			}
			assert.Equal(t, tt.wantCount, pks.expire())
			assert.Equal(t, tt.wantFields.data, pks.data)
		})
	}
}

func Test_peerKnowledgeSet_peerKnows(t *testing.T) {
	now := time.Now()
	expires := now.Add(DefaultFactTTL)
	offset := DefaultFactTTL / 2
	k1 := testutils.MustKey(t)
	k1p := &wgtypes.Peer{PublicKey: k1}
	ep1 := testutils.RandUDP4Addr(t)

	type fields struct {
		data map[peerKnowledgeKey]time.Time
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
		{
			"empty knows nothing",
			fields{map[peerKnowledgeKey]time.Time{}},
			args{
				k1p,
				facts.EndpointFactFull(ep1, &k1, expires),
				DefaultFactTTL,
			},
			false,
		},
		{
			"same fact known with no hysteresis",
			fields{map[peerKnowledgeKey]time.Time{
				keyOf(facts.EndpointFactFull(ep1, &k1, expires), k1): expires,
			}},
			args{
				k1p,
				facts.EndpointFactFull(ep1, &k1, expires),
				0,
			},
			true,
		},
		{
			"old fact known with hysteresis",
			fields{map[peerKnowledgeKey]time.Time{
				keyOf(facts.EndpointFactFull(ep1, &k1, expires.Add(-offset)), k1): expires.Add(-offset),
			}},
			args{
				k1p,
				facts.EndpointFactFull(ep1, &k1, expires),
				offset,
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data: tt.fields.data,
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
		peer wgtypes.Key
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantAlive  bool
		wantUntil  time.Time
		wantBootID *uuid.UUID
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				data:    tt.fields.data,
				bootIDs: tt.fields.bootIDs,
			}
			gotAlive, aliveUntil, gotBootID := pks.peerAlive(tt.args.peer)
			assert.Equal(t, tt.wantAlive, gotAlive)
			assert.Equal(t, tt.wantUntil, aliveUntil)
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
			}
			pks.forcePing(tt.args.self, tt.args.peer)
			assert.Equal(t, tt.wantFields.data, pks.data)
			assert.Equal(t, tt.wantFields.bootIDs, pks.bootIDs)
		})
	}
}

func Test_peerKnowledgeSet_peerBootID(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)
	u1 := uuid.Must(uuid.NewRandom())

	type fields struct {
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
		{
			"known",
			fields{map[wgtypes.Key]uuid.UUID{k1: u1}},
			args{k1},
			&u1,
		},
		{
			"unknown",
			fields{map[wgtypes.Key]uuid.UUID{k1: u1}},
			args{k2},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pks := &peerKnowledgeSet{
				bootIDs: tt.fields.bootIDs,
			}
			assert.Equal(t, tt.want, pks.peerBootID(tt.args.peer))
		})
	}
}
