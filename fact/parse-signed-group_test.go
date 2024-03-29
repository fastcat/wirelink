package fact

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fastcat/wirelink/internal/testutils"
)

func TestParseSignedGroup_Trivial(t *testing.T) {
	now := time.Now()

	// trivial test: inner is one empty fact
	// crypto here is all faked

	// make up some data to verify it's copied around properly
	mockSubjectKey := testutils.MustKey(t)
	mockSignerKey := testutils.MustKey(t)
	var mockNonce [chacha20poly1305.NonceSizeX]byte
	var mockTag [chacha20poly1305.Overhead]byte
	testutils.MustRandBytes(t, mockNonce[:])
	testutils.MustRandBytes(t, mockTag[:])
	mockBootID := uuid.Must(uuid.NewRandom())

	// TODO: use mock data for TTL, hard because clock moves

	_, p := mustMockAlivePacket(t, &mockSubjectKey, &mockBootID)

	_, p = mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{Key: mockSignerKey},
		Expires:   time.Time{},
		Value: &SignedGroupValue{
			Nonce:      mockNonce,
			Tag:        mockTag,
			InnerBytes: p,
		},
	})

	f := mustDeserialize(t, p, now)
	assert.Equal(t, AttributeSignedGroup, f.Attribute)

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, mockSignerKey, f.Subject.(*PeerSubject).Key, "parsed signer subject should be correct")
		assert.False(t, f.Expires.After(time.Now()), "Parsed expires should be <= now")
	}

	if assert.IsType(t, &SignedGroupValue{}, f.Value) {
		sgv := f.Value.(*SignedGroupValue)
		assert.Equal(t, mockNonce, sgv.Nonce, "Parsed nonce should be zeros")
		assert.Equal(t, mockTag, sgv.Tag, "Parsed tag should be zeros")

		f = mustDeserialize(t, sgv.InnerBytes, now)
		assert.Equal(t, AttributeAlive, f.Attribute, "SGV inner attr")
		if assert.IsType(t, &PeerSubject{}, f.Subject) {
			assert.Equal(t, mockSubjectKey, f.Subject.(*PeerSubject).Key, "SGV inner subject should be correct")
		}
		assert.False(t, f.Expires.After(time.Now()), "SGV inner expires should be <= now")
		if assert.IsType(t, &UUIDValue{}, f.Value) {
			assert.Equal(t, &UUIDValue{UUID: mockBootID}, f.Value, "SGV inner uuid should be preserved")
		}
	}
}

func TestParseSignedGroup_Large(t *testing.T) {
	now := time.Now()
	longBytes := make([]byte, chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead+1500)
	// rand never returns partial results
	_, err := rand.Read(longBytes)
	require.Nil(t, err)
	sgv := &SignedGroupValue{}
	const l1 = chacha20poly1305.NonceSizeX
	const l2 = l1 + chacha20poly1305.Overhead
	copy(sgv.Nonce[:], longBytes[0:l1])
	copy(sgv.Tag[:], longBytes[l1:l2])
	sgv.InnerBytes = longBytes[l2:]
	_, p := mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{},
		Expires:   time.Time{},
		Value:     sgv,
	})
	assert.GreaterOrEqual(t, len(p), len(longBytes))
	require.NotEqual(t, p[0], 0)
	f := mustDeserialize(t, p, now)
	if assert.IsType(t, &SignedGroupValue{}, f.Value) {
		assert.Equal(t, longBytes[0:l1], f.Value.(*SignedGroupValue).Nonce[:])
		assert.Equal(t, longBytes[l1:l2], f.Value.(*SignedGroupValue).Tag[:])
		assert.Equal(t, longBytes[l2:], f.Value.(*SignedGroupValue).InnerBytes[:])
	}
}

func TestParseSignedGroup_Inner(t *testing.T) {
	now := time.Now()

	// use a sequence of UUID packets for simplicity
	// as with the trivial test, crypto here is all faked

	// make up some data to verify it's copied around properly
	mockSignerKey := testutils.MustKey(t)
	var mockNonce [chacha20poly1305.NonceSizeX]byte
	var mockTag [chacha20poly1305.Overhead]byte
	testutils.MustRandBytes(t, mockNonce[:])
	testutils.MustRandBytes(t, mockTag[:])

	// TODO: use mock data for TTL, hard because clock moves

	f1, p1 := mustMockAlivePacket(t, nil, nil)
	f2, p2 := mustMockAlivePacket(t, nil, nil)
	fi := []*Fact{f1, f2}
	inner := make([]byte, 0, len(p1)+len(p2))
	inner = append(inner, p1...)
	inner = append(inner, p2...)

	_, p := mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{Key: mockSignerKey},
		Expires:   time.Time{},
		Value: &SignedGroupValue{
			Nonce:      mockNonce,
			Tag:        mockTag,
			InnerBytes: inner,
		},
	})

	f := mustDeserialize(t, p, now)
	assert.Equal(t, AttributeSignedGroup, f.Attribute)

	if assert.IsType(t, &PeerSubject{}, f.Subject) {
		assert.Equal(t, mockSignerKey, f.Subject.(*PeerSubject).Key, "parsed signer subject should be correct")
		assert.Equal(t, now, f.Expires, "Parsed expires should be = now")
	}

	if assert.IsType(t, &SignedGroupValue{}, f.Value) {
		sgv := f.Value.(*SignedGroupValue)
		assert.Equal(t, mockNonce, sgv.Nonce, "Parsed nonce should be preserved")
		assert.Equal(t, mockTag, sgv.Tag, "Parsed tag should be preserved")

		fip, err := sgv.ParseInner(now)
		require.Nil(t, err)
		assert.Len(t, fip, 2)

		// cspell: ignore fipi
		for i, fipi := range fip {
			assert.Equalf(t, AttributeAlive, fipi.Attribute, "SGV inner#%d attr", i)
			if assert.IsTypef(t, &PeerSubject{}, fipi.Subject, "SGV inner#%d subject type", i) {
				assert.Equalf(t, fi[i].Subject.(*PeerSubject).Key, fipi.Subject.(*PeerSubject).Key, "SGV inner#%d subject should be correct", i)
			}
			assert.Falsef(t, fipi.Expires.After(now), "SGV inner#%d expires should be <= now", i)
			if assert.IsTypef(t, &UUIDValue{}, fipi.Value, "SGV inner#%d value type", i) {
				assert.Equalf(t, fi[i].Value, fipi.Value, "SGV inner#%d uuid should be preserved", i)
			}
		}
	}
}
