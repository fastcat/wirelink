package apply

import (
	"testing"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_EnsurePeerAutoIP_Rebuild(t *testing.T) {
	peer := makePeer(t)
	autoaddr := autopeer.AutoAddressNet(peer.PublicKey)
	peer.AllowedIPs = append(peer.AllowedIPs, autoaddr)

	pcfg := &wgtypes.PeerConfig{
		PublicKey:         peer.PublicKey,
		ReplaceAllowedIPs: true,
	}

	pcfg, added := EnsurePeerAutoIP(peer, pcfg)

	// re-adding shouldn't be logged
	assert.False(t, added)
	assert.Contains(t, pcfg.AllowedIPs, autoaddr)
}
