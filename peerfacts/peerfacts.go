package peerfacts

import (
	"fmt"
	"time"

	"github.com/fastcat/wirelink/fact"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LocalFacts gets all the known facts about a local peer
func LocalFacts(peer *wgtypes.Peer, ttl time.Duration) (ret []fact.Fact, err error) {
	if peer == nil {
		return nil, fmt.Errorf("No peer")
	}
	if ttl.Seconds() < 0 || ttl.Seconds() > 255 {
		return nil, fmt.Errorf("ttl out of range")
	}

	// TODO: this is just a placeholder
	ret = append(ret, fact.Fact{
		Attribute: fact.AttributeUnknown,
		Subject:   peer.PublicKey[:],
		Value:     peer.PublicKey[:],
		Expires:   time.Now().Add(ttl),
	})

	return ret, nil
}
