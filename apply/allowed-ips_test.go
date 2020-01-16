package apply

import (
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fastcat/wirelink/autopeer"
	"github.com/fastcat/wirelink/fact"
	"github.com/fastcat/wirelink/internal/testutils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func makePeer(t *testing.T) *wgtypes.Peer {
	var peer wgtypes.Peer

	peer.PublicKey = testutils.MustKey(t)

	return &peer
}

func makeIPNet(t *testing.T) net.IPNet {
	return net.IPNet{
		IP:   testutils.MustRandBytes(t, make([]byte, net.IPv4len)),
		Mask: net.CIDRMask(1+rand.Intn(8*net.IPv4len), 8*net.IPv4len),
	}
}

func makeAIP(t *testing.T, peer *wgtypes.Peer, aip *net.IPNet) (aipFact *fact.Fact, ipn net.IPNet) {
	if aip == nil {
		ipn = makeIPNet(t)
	} else {
		ipn = *aip
	}
	aipFact = &fact.Fact{
		Subject:   &fact.PeerSubject{Key: peer.PublicKey},
		Attribute: fact.AttributeAllowedCidrV4,
		Value:     &fact.IPNetValue{IPNet: ipn},
	}
	return
}

func Test_EnsureAllowedIPs_Nil(t *testing.T) {
	peer := makePeer(t)
	pc := EnsureAllowedIPs(peer, nil, nil, false)

	// no input config, nothing to do => no output
	assert.Nil(t, pc)
}

func Test_EnsureAllowedIPs_AddOne(t *testing.T) {
	peer := makePeer(t)
	var facts []*fact.Fact
	fact, aip := makeAIP(t, peer, nil)
	facts = append(facts, fact)

	pc := EnsureAllowedIPs(peer, facts, nil, false)

	require.NotNil(t, pc)
	require.Len(t, pc.AllowedIPs, 1)
	assert.EqualValues(t, aip, pc.AllowedIPs[0])
}

func Test_EnsureAllowedIPs_RemoveOnly(t *testing.T) {
	peer := makePeer(t)
	peer.AllowedIPs = append(peer.AllowedIPs, makeIPNet(t))
	autoAddr := autopeer.AutoAddressNet(peer.PublicKey)
	peer.AllowedIPs = append(peer.AllowedIPs, autoAddr)

	pc := EnsureAllowedIPs(peer, nil, nil, true)

	require.NotNil(t, pc)
	assert.Len(t, pc.AllowedIPs, 1)
	assert.True(t, pc.ReplaceAllowedIPs)
	assert.Contains(t, pc.AllowedIPs, autoAddr)
}

func Test_EnsureAllowedIPs_ReplaceOnly(t *testing.T) {
	peer := makePeer(t)
	peer.AllowedIPs = append(peer.AllowedIPs, makeIPNet(t))
	var facts []*fact.Fact
	fact, aip := makeAIP(t, peer, nil)
	facts = append(facts, fact)

	pc := EnsureAllowedIPs(peer, facts, nil, true)

	require.NotNil(t, pc)
	require.Len(t, pc.AllowedIPs, 2)
	assert.True(t, pc.ReplaceAllowedIPs)
	assert.Contains(t, pc.AllowedIPs, aip)
	assert.Contains(t, pc.AllowedIPs, autopeer.AutoAddressNet(peer.PublicKey))
}

func Test_EnsureAllowedIPs_ReplaceOne(t *testing.T) {
	peer := makePeer(t)
	autoAddr := autopeer.AutoAddressNet(peer.PublicKey)
	peer.AllowedIPs = append(peer.AllowedIPs, autoAddr)
	peer.AllowedIPs = append(peer.AllowedIPs, makeIPNet(t))
	keepAip := makeIPNet(t)
	peer.AllowedIPs = append(peer.AllowedIPs, keepAip)
	var facts []*fact.Fact
	fact, _ := makeAIP(t, peer, &keepAip)
	facts = append(facts, fact)
	fact, newAip := makeAIP(t, peer, nil)
	facts = append(facts, fact)

	pc := EnsureAllowedIPs(peer, facts, nil, true)

	require.NotNil(t, pc)
	require.Len(t, pc.AllowedIPs, 3)
	assert.True(t, pc.ReplaceAllowedIPs)
	assert.Contains(t, pc.AllowedIPs, keepAip)
	assert.Contains(t, pc.AllowedIPs, newAip)
	assert.Contains(t, pc.AllowedIPs, autoAddr)
}
