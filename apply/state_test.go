package apply

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeerConfigState_EnsureNotNil(t *testing.T) {
	tests := []struct {
		name string
		pcs  *PeerConfigState
		want *PeerConfigState
	}{
		{"nil", nil, &PeerConfigState{endpointLastUsed: make(map[string]time.Time)}},
		{"not-nil", &PeerConfigState{}, &PeerConfigState{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pcs.EnsureNotNil()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPeerConfigState_Update(t *testing.T) {
	name := fmt.Sprintf("p%d", rand.Int())

	now := time.Now()
	t1 := now.Add(time.Duration(-1-rand.Intn(60)) * time.Second)
	t2 := t1.Add(time.Duration(-1-rand.Intn(60)) * time.Second)

	u1 := uuid.Must(uuid.NewRandom())
	u2 := uuid.Must(uuid.NewRandom())

	type fields struct {
		nil bool

		lastHandshake    time.Time
		lastHealthy      bool
		lastAlive        bool
		lastBootID       *uuid.UUID
		aliveSince       time.Time
		endpointLastUsed map[string]time.Time
	}
	type args struct {
		peer       *wgtypes.Peer
		name       string
		newAlive   bool
		aliveUntil time.Time
		bootID     *uuid.UUID
		now        time.Time
		facts      []*fact.Fact
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *PeerConfigState
	}{
		{
			"initialize healthy peer",
			fields{nil: true},
			args{
				peer: &wgtypes.Peer{
					LastHandshakeTime: t1,
					Endpoint:          testutils.RandUDP4Addr(t),
				},
				name:     name,
				newAlive: true,
				bootID:   &u1,
				now:      now,
			},
			&PeerConfigState{
				lastHandshake:    t1,
				lastHealthy:      true,
				lastAlive:        true,
				lastBootID:       &u1,
				aliveSince:       now,
				endpointLastUsed: map[string]time.Time{},
			},
		},
		{
			"update healthy peer",
			fields{
				lastHandshake:    t2,
				lastHealthy:      true,
				lastAlive:        true,
				lastBootID:       &u1,
				aliveSince:       t2,
				endpointLastUsed: map[string]time.Time{},
			},
			args{
				peer: &wgtypes.Peer{
					LastHandshakeTime: t1,
					Endpoint:          testutils.RandUDP4Addr(t),
				},
				name:     name,
				newAlive: true,
				bootID:   &u1,
				now:      now,
			},
			&PeerConfigState{
				lastHandshake:    t1,
				lastHealthy:      true,
				lastAlive:        true,
				lastBootID:       &u1,
				aliveSince:       t2,
				endpointLastUsed: map[string]time.Time{},
			},
		},
		{
			"reboot healthy peer",
			fields{
				lastHandshake:    t2,
				lastHealthy:      true,
				lastAlive:        true,
				lastBootID:       &u1,
				aliveSince:       t2,
				endpointLastUsed: map[string]time.Time{},
			},
			args{
				peer: &wgtypes.Peer{
					LastHandshakeTime: t1,
					Endpoint:          testutils.RandUDP4Addr(t),
				},
				name:     name,
				newAlive: true,
				bootID:   &u2,
				now:      now,
			},
			&PeerConfigState{
				lastHandshake:    t1,
				lastHealthy:      true,
				lastAlive:        true,
				lastBootID:       &u2,
				aliveSince:       now,
				endpointLastUsed: map[string]time.Time{},
			},
		},
		{
			"unhealthy peer comes alive",
			fields{
				lastHandshake:    t2,
				lastHealthy:      false,
				lastAlive:        false,
				lastBootID:       &u1,
				aliveSince:       t2,
				endpointLastUsed: map[string]time.Time{},
			},
			args{
				peer: &wgtypes.Peer{
					LastHandshakeTime: t1,
					Endpoint:          testutils.RandUDP4Addr(t),
				},
				name:     name,
				newAlive: true,
				bootID:   &u1,
				now:      now,
			},
			&PeerConfigState{
				lastHandshake:    t1,
				lastHealthy:      true,
				lastAlive:        true,
				lastBootID:       &u1,
				aliveSince:       now,
				endpointLastUsed: map[string]time.Time{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcs := &PeerConfigState{
				lastHandshake:    tt.fields.lastHandshake,
				lastHealthy:      tt.fields.lastHealthy,
				lastAlive:        tt.fields.lastAlive,
				lastBootID:       tt.fields.lastBootID,
				aliveSince:       tt.fields.aliveSince,
				endpointLastUsed: tt.fields.endpointLastUsed,
			}
			if tt.fields.nil {
				pcs = nil
			}
			got := pcs.Update(tt.args.peer, tt.args.name, tt.args.newAlive, tt.args.aliveUntil, tt.args.bootID, tt.args.now, tt.args.facts, false)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPeerConfigState_Describe(t *testing.T) {
	now := time.Now()

	type fields struct {
		nil bool

		lastHandshake    time.Time
		lastHealthy      bool
		lastAlive        bool
		lastBootID       *uuid.UUID
		aliveSince       time.Time
		endpointLastUsed map[string]time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		want    []string
		notWant []string
	}{
		{
			"nil",
			fields{nil: true},
			[]string{"?"},
			[]string{"health", "live"},
		},
		{
			"live",
			fields{lastHealthy: true, lastAlive: true, lastHandshake: now},
			[]string{"healthy", "alive"},
			[]string{"unhealthy", "not alive", "?"},
		},
		{
			"half alive",
			fields{lastHealthy: true, lastAlive: false, lastHandshake: now},
			[]string{"healthy", "not alive"},
			[]string{"unhealthy", "?"},
		},
		{
			"zombie",
			fields{lastHealthy: false, lastAlive: true},
			[]string{"unhealthy", "alive", "?"},
			[]string{"not alive"},
		},
		{
			"dead",
			fields{lastHealthy: false, lastAlive: false},
			[]string{"unhealthy"},
			[]string{"?"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcs := &PeerConfigState{
				lastHandshake:    tt.fields.lastHandshake,
				lastHealthy:      tt.fields.lastHealthy,
				lastAlive:        tt.fields.lastAlive,
				lastBootID:       tt.fields.lastBootID,
				aliveSince:       tt.fields.aliveSince,
				endpointLastUsed: tt.fields.endpointLastUsed,
			}
			if tt.fields.nil {
				pcs = nil
			}
			got := pcs.Describe(now)
			for _, substr := range tt.want {
				assert.Contains(t, got, substr)
			}
			for _, substr := range tt.notWant {
				assert.NotContains(t, got, substr)
			}
		})
	}
}

func TestPeerConfigState_TimeForNextEndpoint(t *testing.T) {
	now := time.Now()
	// t1 is before now, but not too far
	t1 := now.Add(time.Duration(-1-rand.Intn(14)) * time.Second)
	// t2 is far enough before now it should be expired
	t2 := t1.Add(time.Duration(-16-rand.Intn(60)) * time.Second)
	// t3 is similarly far behind t2
	t3 := t2.Add(time.Duration(-16-rand.Intn(60)) * time.Second)

	e1 := testutils.RandUDP4Addr(t)
	e2 := testutils.RandUDP4Addr(t)
	e1fk := string(util.MustBytes(facts.EndpointValue(e1).MarshalBinary()))
	e2fk := string(util.MustBytes(facts.EndpointValue(e2).MarshalBinary()))

	type fields struct {
		nil bool

		lastHandshake    time.Time
		lastHealthy      bool
		lastAlive        bool
		lastBootID       *uuid.UUID
		aliveSince       time.Time
		endpointLastUsed map[string]time.Time
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"nil", fields{nil: true}, true},
		{"no history", fields{}, true},
		{"healthy", fields{lastHealthy: true}, false},
		{
			"freshly used endpoint",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: now,
				},
			},
			false,
		},
		{
			"one recent one old",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: t1,
					e2fk: t2,
				},
			},
			false,
		},
		{
			"two old",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: t2,
					e2fk: t3,
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcs := &PeerConfigState{
				lastHandshake:    tt.fields.lastHandshake,
				lastHealthy:      tt.fields.lastHealthy,
				lastAlive:        tt.fields.lastAlive,
				lastBootID:       tt.fields.lastBootID,
				aliveSince:       tt.fields.aliveSince,
				endpointLastUsed: tt.fields.endpointLastUsed,
			}
			if tt.fields.nil {
				pcs = nil
			}
			got := pcs.TimeForNextEndpoint()
			t.Logf("deltas: %v, %v, %v", now.Sub(t1), t1.Sub(t2), t2.Sub(t3))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPeerConfigState_NextEndpoint(t *testing.T) {
	now := time.Now()
	// t1 is before now, but not too far
	t1 := now.Add(time.Duration(-1-rand.Intn(15)) * time.Second)
	// t2 is far enough before now it should be expired
	t2 := t1.Add(time.Duration(-15-rand.Intn(60)) * time.Second)
	// t3 is similarly far behind t2
	// t3 := t2.Add(time.Duration(-15-rand.Intn(60)) * time.Second)

	e1 := testutils.RandUDP4Addr(t)
	e2 := testutils.RandUDP4Addr(t)
	e3 := testutils.RandUDP4Addr(t)
	e1fk := string(util.MustBytes(facts.EndpointValue(e1).MarshalBinary()))
	e2fk := string(util.MustBytes(facts.EndpointValue(e2).MarshalBinary()))
	// e3fk := string(util.MustBytes(facts.EndpointValue(e3).MarshalBinary()))

	type fields struct {
		// NextEndpoint doesn't allow a nil receiver
		// nil bool

		lastHandshake    time.Time
		lastHealthy      bool
		lastAlive        bool
		lastBootID       *uuid.UUID
		aliveSince       time.Time
		endpointLastUsed map[string]time.Time
	}
	type args struct {
		peerFacts []*fact.Fact
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *net.UDPAddr
	}{
		{"nil facts", fields{}, args{}, nil},
		{
			"lost facts",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: now,
				},
			},
			args{
				peerFacts: []*fact.Fact{},
			},
			nil,
		},
		{
			"only one choice",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: t1,
				},
			},
			args{
				peerFacts: []*fact.Fact{
					facts.EndpointFact(e1),
				},
			},
			e1,
		},
		{
			"two equal choices",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: t1,
					e2fk: t1,
				},
			},
			args{
				peerFacts: []*fact.Fact{
					// order matters here for the result
					facts.EndpointFact(e2),
					facts.EndpointFact(e1),
				},
			},
			e2,
		},
		{
			"two ordered choices",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: t1,
					e2fk: t2,
				},
			},
			args{
				peerFacts: []*fact.Fact{
					facts.EndpointFact(e2),
					facts.EndpointFact(e1),
				},
			},
			e2,
		},
		{
			"new and old",
			fields{
				lastHealthy: false,
				endpointLastUsed: map[string]time.Time{
					e1fk: t1,
					e2fk: t2,
				},
			},
			args{
				peerFacts: []*fact.Fact{
					facts.EndpointFact(e2),
					facts.EndpointFact(e3),
				},
			},
			e3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcs := &PeerConfigState{
				lastHandshake:    tt.fields.lastHandshake,
				lastHealthy:      tt.fields.lastHealthy,
				lastAlive:        tt.fields.lastAlive,
				lastBootID:       tt.fields.lastBootID,
				aliveSince:       tt.fields.aliveSince,
				endpointLastUsed: tt.fields.endpointLastUsed,
			}
			// if tt.fields.nil {
			// 	pcs = nil
			// }
			got := pcs.NextEndpoint("test", tt.args.peerFacts, now, nil)
			assert.Equal(t, tt.want, got)
			if tt.want != nil {
				wantMap := make(map[string]time.Time, len(tt.fields.endpointLastUsed))
				for k, v := range tt.fields.endpointLastUsed {
					wantMap[k] = v
				}
				wantMap[string(util.MustBytes(facts.EndpointValue(tt.want).MarshalBinary()))] = now
				assert.Equal(t, wantMap, pcs.endpointLastUsed)
			}
		})
	}
}

func TestPeerConfigState_Clone(t *testing.T) {
	u1 := uuid.Must(uuid.NewRandom())

	type fields struct {
		lastHandshake    time.Time
		lastHealthy      bool
		lastAlive        bool
		lastBootID       *uuid.UUID
		aliveSince       time.Time
		endpointLastUsed map[string]time.Time
	}
	tests := []struct {
		name   string
		fields *fields
	}{
		{
			"nil",
			nil,
		},
		{
			"empty",
			&fields{endpointLastUsed: map[string]time.Time{}},
		},
		{
			"filled",
			&fields{
				time.Now(),
				true,
				true,
				&u1,
				time.Now(),
				map[string]time.Time{
					"a": time.Now(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pcs *PeerConfigState
			if tt.fields != nil {
				pcs = &PeerConfigState{
					lastHandshake:    tt.fields.lastHandshake,
					lastHealthy:      tt.fields.lastHealthy,
					lastAlive:        tt.fields.lastAlive,
					lastBootID:       tt.fields.lastBootID,
					aliveSince:       tt.fields.aliveSince,
					endpointLastUsed: tt.fields.endpointLastUsed,
				}
			}
			got := pcs.Clone()
			if tt.fields == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, pcs, got)
			assert.False(t, pcs == got)
			if pcs.lastBootID != nil {
				assert.False(t, pcs.lastBootID == got.lastBootID)
			}
			// can't do == on maps, so have to do something else
			assert.NotEqual(t, reflect.ValueOf(pcs.endpointLastUsed).Pointer(), reflect.ValueOf(got.endpointLastUsed).Pointer())
			// everything else are simple values
		})
	}
}

func TestPeerConfigState_IsHealthy(t *testing.T) {
	type fields struct {
		lastHealthy bool
	}
	tests := []struct {
		name   string
		fields *fields
		want   bool
	}{
		{"nil", nil, false},
		{"unhealthy", &fields{false}, false},
		{"healthy", &fields{true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pcs *PeerConfigState
			if tt.fields != nil {
				pcs = &PeerConfigState{
					lastHealthy: tt.fields.lastHealthy,
				}
			}
			assert.Equal(t, tt.want, pcs.IsHealthy())
		})
	}
}

func TestPeerConfigState_IsAlive(t *testing.T) {
	type fields struct {
		lastAlive bool
	}
	tests := []struct {
		name   string
		fields *fields
		want   bool
	}{
		{"nil", nil, false},
		{"not alive", &fields{false}, false},
		{"alive", &fields{true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pcs *PeerConfigState
			if tt.fields != nil {
				pcs = &PeerConfigState{
					lastAlive: tt.fields.lastAlive,
				}
			}
			assert.Equal(t, tt.want, pcs.IsAlive())
		})
	}
}

func TestPeerConfigState_AliveSince(t *testing.T) {
	now := time.Now()

	type fields struct {
		lastHealthy bool
		lastAlive   bool
		aliveSince  time.Time
	}
	tests := []struct {
		name   string
		fields *fields
		want   time.Time
	}{
		{"nil", nil, util.TimeMax()},
		{"unhealthy", &fields{false, true, now}, util.TimeMax()},
		{"not alive", &fields{true, false, now}, util.TimeMax()},
		{"healthy and alive", &fields{true, true, now}, now},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pcs *PeerConfigState
			if tt.fields != nil {
				pcs = &PeerConfigState{
					lastHealthy: tt.fields.lastHealthy,
					lastAlive:   tt.fields.lastAlive,
					aliveSince:  tt.fields.aliveSince,
				}
			}
			assert.Equal(t, tt.want, pcs.AliveSince())
		})
	}
}
