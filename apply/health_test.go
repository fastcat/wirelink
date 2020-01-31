package apply

import (
	"math/rand"
	"time"

	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_isHealthy(t *testing.T) {
	now := time.Now()
	then := now.Add(time.Duration(-rand.Intn(30)) * time.Second)
	longAgo := now.Add(-HandshakeValidity)
	longLongAgo := then.Add(-HandshakeValidity)

	type args struct {
		state *PeerConfigState
		peer  *wgtypes.Peer
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"no endpoint",
			args{
				peer: &wgtypes.Peer{},
			},
			false,
		},
		{
			"fresh handshake",
			args{
				peer: &wgtypes.Peer{
					Endpoint:          testutils.RandUDP4Addr(t),
					LastHandshakeTime: now,
				},
			},
			true,
		},
		{
			"changed stale handshake",
			args{
				peer: &wgtypes.Peer{
					Endpoint:          testutils.RandUDP4Addr(t),
					LastHandshakeTime: longAgo,
				},
				state: &PeerConfigState{
					lastHandshake: longLongAgo,
				},
			},
			true,
		},
		{
			"stable stale handshake",
			args{
				peer: &wgtypes.Peer{
					Endpoint:          testutils.RandUDP4Addr(t),
					LastHandshakeTime: longAgo,
				},
				state: &PeerConfigState{
					lastHandshake: longAgo,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHealthy(tt.args.state, tt.args.peer)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsHandshakeHealthy(t *testing.T) {
	now := time.Now()
	then := now.Add(time.Duration(rand.Int63n(30)) * time.Second)
	longAgo := now.Add(-HandshakeValidity)

	type args struct {
		lastHandshake time.Time
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"very fresh", args{now}, true},
		{"fresh", args{then}, true},
		{"stale", args{longAgo}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHandshakeHealthy(tt.args.lastHandshake)
			assert.Equal(t, tt.want, got)
		})
	}
}
