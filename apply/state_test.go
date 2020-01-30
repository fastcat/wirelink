package apply

import (
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stretchr/testify/assert"

	"github.com/fastcat/wirelink/fact"

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
	type fields struct {
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
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *PeerConfigState
	}{
		// TODO: Add test cases.
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
			got := pcs.Update(tt.args.peer, tt.args.name, tt.args.newAlive, tt.args.bootID)
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
		{"healthy", fields{lastHealthy: true}, false},
		{"no endpoints", fields{}, false},
		// TODO: Add test cases.
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
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPeerConfigState_NextEndpoint(t *testing.T) {
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
		// TODO: Add test cases.
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
			got := pcs.NextEndpoint(tt.args.peerFacts)
			assert.Equal(t, tt.want, got)
		})
	}
}
