package fact

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/fastcat/wirelink/signing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccumulatorLimits(t *testing.T) {
	ef, ep := mustMockAlivePacket(t, nil, nil)

	a := NewAccumulator(len(ep)*4-1, time.Now())

	for i := 0; i < 4; i++ {
		err := a.AddFact(ef)
		require.Nil(t, err)
	}

	require.Len(t, a.groups, 2, "Should split into 2 groups")
	assert.Len(t, a.groups[0], len(ep)*3, "Should have 3 packets in group 1")
	assert.Len(t, a.groups[1], len(ep), "Should have 1 packet in group 2")
}

func TestAccumulatorSigning(t *testing.T) {
	ef, ep := mustMockAlivePacket(t, nil, nil)

	a := NewAccumulator(len(ep)*4-1, time.Now())
	for i := 0; i < 4; i++ {
		err := a.AddFact(ef)
		require.Nil(t, err)
	}

	priv, signer := testutils.MustKeyPair(t)
	_, pub := testutils.MustKeyPair(t)

	s := signing.New(priv)

	facts, err := a.MakeSignedGroups(s, &pub)
	require.Nil(t, err)

	require.Len(t, facts, 2, "Should have two SignedGroupValues")

	for i, sf := range facts {
		assert.Equal(t, AttributeSignedGroup, sf.Attribute, "Signing output should be SignedGroups")
		assert.IsType(t, &PeerSubject{}, sf.Subject)
		// the subject must be the public key of the signer, _not the recipient_
		assert.Equal(t, signer, sf.Subject.(*PeerSubject).Key)
		assert.False(t, sf.Expires.After(time.Now()), "Expiration should be <= now")
		require.IsType(t, &SignedGroupValue{}, sf.Value, "SG Value should be an SGV")
		sgv := sf.Value.(*SignedGroupValue)

		// signing checks are handled elsewhere
		if i == 0 {
			assert.Len(t, sgv.InnerBytes, len(ep)*3, "Should have 3 facts in first packet")
		} else if i == 1 {
			assert.Len(t, sgv.InnerBytes, len(ep)*1, "Should have 1 fact in second packet")
		} else {
			require.FailNow(t, "WAT?!")
		}
	}
}

func TestGroupAccumulator_AddFactIfRoom_OneByteTooSmall(t *testing.T) {
	f := &Fact{
		Attribute: AttributeAlive,
		Subject:   &PeerSubject{testutils.MustKey(t)},
		Value:     &UUIDValue{uuid.Must(uuid.NewRandom())},
		Expires:   time.Now(),
	}
	b, err := f.MarshalBinary()
	require.Nil(t, err)
	ga := NewAccumulator(len(b)*3-1, time.Now())

	err = ga.AddFact(f)
	require.Nil(t, err)

	added, err := ga.AddFactIfRoom(f)
	require.Nil(t, err)
	assert.True(t, added)

	added, err = ga.AddFactIfRoom(f)
	require.Nil(t, err)
	assert.False(t, added)
}

func TestGroupAccumulator_AddFactIfRoom_JustRight(t *testing.T) {
	f := &Fact{
		Attribute: AttributeAlive,
		Subject:   &PeerSubject{testutils.MustKey(t)},
		Value:     &UUIDValue{uuid.Must(uuid.NewRandom())},
		Expires:   time.Now(),
	}
	b, err := f.MarshalBinary()
	require.Nil(t, err)
	ga := NewAccumulator(len(b)*2, time.Now())

	err = ga.AddFact(f)
	require.Nil(t, err)

	added, err := ga.AddFactIfRoom(f)
	require.Nil(t, err)
	assert.True(t, added)
}
