package server

import (
	"testing"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func makePCS(t *testing.T, healthy, alive, aliveLong bool) *apply.PeerConfigState {
	ret := &apply.PeerConfigState{}
	now := time.Now()
	handshake := now
	if !healthy {
		handshake = now.Add(-time.Hour)
	}
	if aliveLong {
		now = now.Add(-FactTTL)
	}
	ret.Update(
		&wgtypes.Peer{
			LastHandshakeTime: handshake,
			Endpoint:          testutils.RandUDP4Addr(t),
		},
		"",
		alive,
		nil,
		now,
	)
	// make sure it worked
	assert.Equal(t, healthy, ret.IsHealthy())
	assert.Equal(t, alive, ret.IsAlive())
	return ret
}
