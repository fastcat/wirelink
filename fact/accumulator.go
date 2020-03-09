package fact

import (
	"time"

	"github.com/pkg/errors"

	"github.com/fastcat/wirelink/signing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// GroupAccumulator is a helper to aggregate individual facts into (signed)
// groups of a max size
type GroupAccumulator struct {
	maxGroupLen int
	groups      [][]byte
	now         time.Time
}

// NewAccumulator initializes a new GroupAccumulator with a given max inner
// size per group.
func NewAccumulator(maxGroupLen int, now time.Time) *GroupAccumulator {
	return &GroupAccumulator{
		maxGroupLen: maxGroupLen,
		groups:      make([][]byte, 1),
		now:         now,
	}
}

// AddFact appends the given fact into the accumulator
func (ga *GroupAccumulator) AddFact(f *Fact) error {
	b, err := f.MarshalBinaryNow(ga.now)
	if err != nil {
		return errors.Wrapf(err, "Unable to convert fact to packet bytes")
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

// AddFactIfRoom conditionally adds the fact if and only if it won't result in
// creating a new group
func (ga *GroupAccumulator) AddFactIfRoom(f *Fact) (added bool, err error) {
	b, err := f.MarshalBinaryNow(ga.now)
	if err != nil {
		return false, errors.Wrapf(err, "Unable to convert fact to packet bytes")
	}
	lgi := len(ga.groups) - 1
	lg := ga.groups[lgi]
	if len(lg)+len(b) > ga.maxGroupLen || len(lg) == 0 {
		return false, nil
	}
	ga.groups[lgi] = append(lg, b...)
	return true, nil
}

// MakeSignedGroups converts all the accumulated facts into SignedGroups of no
// more than the specified max inner size.
func (ga *GroupAccumulator) MakeSignedGroups(
	s *signing.Signer,
	recipient *wgtypes.Key,
) ([]*Fact, error) {
	ret := make([]*Fact, 0, len(ga.groups))
	subject := PeerSubject{Key: s.PublicKey}
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
		ret = append(ret, &Fact{
			Attribute: AttributeSignedGroup,
			// zero time will turn into a TTL of zero
			Expires: time.Time{},
			Subject: &subject,
			Value:   &value,
		})
	}
	return ret, nil
}
