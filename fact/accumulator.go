package fact

import (
	"time"

	"github.com/fastcat/wirelink/signing"
	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GroupAccumulator is a helper to aggregate individual facts into (signed)
// groups of a max size
type GroupAccumulator struct {
	maxGroupLen int
	groups      [][]byte
}

// NewAccumulator initializes a new GroupAccumulator with a given max inner
// size per group.
func NewAccumulator(maxGroupLen int) *GroupAccumulator {
	return &GroupAccumulator{
		maxGroupLen: maxGroupLen,
		groups:      make([][]byte, 1),
	}
}

// AddFact appends the given fact into the accumulator
func (ga *GroupAccumulator) AddFact(f *Fact) error {
	p, err := f.ToWire()
	if err != nil {
		return errors.Wrapf(err, "Unable to convert fact to wire")
	}
	b, err := p.Serialize()
	if err != nil {
		return errors.Wrapf(err, "Unable to convert wire form to packet bytes")
	}
	lgi := len(ga.groups) - 1
	lg := ga.groups[lgi]
	if len(lg)+len(b) > ga.maxGroupLen {
		// make another group
		ga.groups = append(ga.groups, b)
	} else {
		ga.groups[lgi] = append(lg, b...)
	}
	return nil
}

// MakeSignedGroups converts all the accumulated facts into SignedGroups of no
// more than the specified max inner size.
func (ga *GroupAccumulator) MakeSignedGroups(
	s *signing.Signer,
	recipient *wgtypes.Key,
) ([]Fact, error) {
	ret := make([]Fact, 0, len(ga.groups))
	subject := PeerSubject{Key: *recipient}
	for _, g := range ga.groups {
		if len(g) == 0 {
			continue
		}
		// TODO: have signer cache shared key
		nonce, tag, err := s.SignFor(g, recipient)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to sign group data")
		}
		value := SignedGroupValue{
			Nonce:      nonce,
			Tag:        tag,
			InnerBytes: g,
		}
		ret = append(ret, Fact{
			Attribute: AttributeSignedGroup,
			// zero time will turn into a TTL of zero
			Expires: time.Time{},
			Subject: &subject,
			Value:   &value,
		})
	}
	return ret, nil
}
