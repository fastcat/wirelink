package server

import (
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/apply"
	"github.com/fastcat/wirelink/config"
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
		now = now.Add(-FactTTL * 2)
	}
	ret.Update(
		&wgtypes.Peer{
			LastHandshakeTime: handshake,
			Endpoint:          testutils.RandUDP4Addr(t),
		},
		"<makePCS-Fake>",
		alive,
		nil,
		now,
	)
	// make sure it worked
	assert.Equal(t, healthy, ret.IsHealthy())
	assert.Equal(t, alive, ret.IsAlive())
	return ret
}

type configBuilder config.Server

func buildConfig(name string) *configBuilder {
	ret := &configBuilder{}
	ret.Iface = name
	return ret
}
func (c *configBuilder) withPeer(key wgtypes.Key, peer *config.Peer) *configBuilder {
	if c == nil {
		c = &configBuilder{}
	}
	if c.Peers == nil {
		c.Peers = make(config.Peers)
	}
	c.Peers[key] = peer
	return c
}

func (c *configBuilder) Build() *config.Server {
	return (*config.Server)(c)
}

func applyMask(ipn net.IPNet) net.IPNet {
	return net.IPNet{
		IP:   ipn.IP.Mask(ipn.Mask),
		Mask: ipn.Mask,
	}
}
