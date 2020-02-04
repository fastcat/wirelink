package apply

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"

	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"
	factutils "github.com/fastcat/wirelink/internal/testutils/facts"
	"github.com/fastcat/wirelink/util"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
		peer     *wgtypes.Peer
		name     string
		newAlive bool
		bootID   *uuid.UUID
		now      time.Time
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
			got := pcs.Update(tt.args.peer, tt.args.name, tt.args.newAlive, tt.args.bootID, tt.args.now)
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
			got := pcs.Describe()
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
	e1fk := string(util.MustBytes(factutils.EndpointValue(e1).MarshalBinary()))
	e2fk := string(util.MustBytes(factutils.EndpointValue(e2).MarshalBinary()))

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
	e1fk := string(util.MustBytes(factutils.EndpointValue(e1).MarshalBinary()))
	e2fk := string(util.MustBytes(factutils.EndpointValue(e2).MarshalBinary()))
	// e3fk := string(util.MustBytes(factutils.EndpointValue(e3).MarshalBinary()))

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
					factutils.EndpointFact(e1),
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
					factutils.EndpointFact(e2),
					factutils.EndpointFact(e1),
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
					factutils.EndpointFact(e2),
					factutils.EndpointFact(e1),
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
					factutils.EndpointFact(e2),
					factutils.EndpointFact(e3),
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
			got := pcs.NextEndpoint(tt.args.peerFacts, now)
			assert.Equal(t, tt.want, got)
			if tt.want != nil {
				wantMap := make(map[string]time.Time, len(tt.fields.endpointLastUsed))
				for k, v := range tt.fields.endpointLastUsed {
					wantMap[k] = v
				}
				wantMap[string(util.MustBytes(factutils.EndpointValue(tt.want).MarshalBinary()))] = now
				assert.Equal(t, wantMap, pcs.endpointLastUsed)
			}
		})
	}
}
