package fact

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

func TestParseSignedGroup_Trivial(t *testing.T) {
	// trivial test: inner is one empty fact
	// crypto here is all empty

	// make up some data to verify it's copied around properly
	mockSubjectKey := mustKey(t)
	mockSignerKey := mustKey(t)
	var mockNonce [chacha20poly1305.NonceSizeX]byte
	var mockTag [poly1305.TagSize]byte
	mustRandBytes(t, mockNonce[:])
	mustRandBytes(t, mockTag[:])
	var mockBootID uuid.UUID
	mustRandBytes(t, mockBootID[:])

	//TODO: use mock data for TTL, hard because clock moves

	f, p := mustMockAlivePacket(t, &mockSubjectKey, &mockBootID)

	f, p = mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{Key: mockSignerKey},
		Expires:   time.Time{},
		Value: &SignedGroupValue{
			Nonce:      mockNonce,
			Tag:        mockTag,
			InnerBytes: p,
		},
	})

	f = mustDeserialize(t, p)
	assert.Equal(t, AttributeSignedGroup, f.Attribute)

	require.IsType(t, &PeerSubject{}, f.Subject)
	s := f.Subject.(*PeerSubject)
	assert.Equal(t, mockSignerKey, s.Key, "parsed signer subject should be correct")
	assert.False(t, f.Expires.After(time.Now()), "Parsed expires should be <= now")

	require.IsType(t, &SignedGroupValue{}, f.Value)
	sgv := f.Value.(*SignedGroupValue)
	assert.Equal(t, mockNonce, sgv.Nonce, "Parsed nonce should be zeros")
	assert.Equal(t, mockTag, sgv.Tag, "Parsed tag should be zeros")

	f = mustDeserialize(t, sgv.InnerBytes)
	assert.Equal(t, AttributeAlive, f.Attribute, "SGV inner attr")
	require.IsType(t, &PeerSubject{}, f.Subject)
	s = f.Subject.(*PeerSubject)
	assert.Equal(t, mockSubjectKey, s.Key, "SGV inner subject should be correct")
	assert.False(t, f.Expires.After(time.Now()), "SGV inner expires should be <= now")
	assert.IsType(t, &UUIDValue{}, f.Value)
	assert.Equal(t, &UUIDValue{UUID: mockBootID}, f.Value, "SGV inner uuid should be all zeros")
}

func TestParseSignedGroup_Large(t *testing.T) {
	longBytes := make([]byte, chacha20poly1305.NonceSizeX+poly1305.TagSize+1500)
	n, err := rand.Read(longBytes)
	sgv := &SignedGroupValue{}
	const l1 = chacha20poly1305.NonceSizeX
	const l2 = l1 + poly1305.TagSize
	copy(sgv.Nonce[:], longBytes[0:l1])
	copy(sgv.Tag[:], longBytes[l1:l2])
	sgv.InnerBytes = longBytes[l2:]
	require.Nil(t, err)
	assert.Equal(t, len(longBytes), n, "Should load random data for full array")
	_, p := mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{},
		Expires:   time.Time{},
		Value:     sgv,
	})
	assert.GreaterOrEqual(t, len(p), len(longBytes))
	require.NotEqual(t, p[0], 0)
	f := mustDeserialize(t, p)
	require.IsType(t, &SignedGroupValue{}, f.Value)
	assert.Equal(t, longBytes[0:l1], f.Value.(*SignedGroupValue).Nonce[:])
	assert.Equal(t, longBytes[l1:l2], f.Value.(*SignedGroupValue).Tag[:])
	assert.Equal(t, longBytes[l2:], f.Value.(*SignedGroupValue).InnerBytes[:])
}
