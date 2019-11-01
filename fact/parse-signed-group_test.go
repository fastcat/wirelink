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

	f, w, p := mustMockAlivePacket(t, &mockSubjectKey, &mockBootID)

	f, w, p = mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{Key: mockSignerKey},
		Expires:   time.Time{},
		Value: &SignedGroupValue{
			Nonce:      mockNonce,
			Tag:        mockTag,
			InnerBytes: p,
		},
	})
	if w.ttl != 0 {
		t.Errorf("Wire TTL is %d, not 0", w.ttl)
	}

	f, w = mustDeserialize(t, p)
	assert.EqualValues(t, 0, w.ttl, "Deserialized TTL should be zero")
	assert.Equal(t, AttributeSignedGroup, f.Attribute)

	require.IsType(t, &PeerSubject{}, f.Subject)
	s := f.Subject.(*PeerSubject)
	assert.Equal(t, mockSignerKey, s.Key, "parsed signer subject should be correct")
	assert.False(t, f.Expires.After(time.Now()), "Parsed expires should be <= now")

	require.IsType(t, &SignedGroupValue{}, f.Value)
	sgv := f.Value.(*SignedGroupValue)
	assert.Equal(t, mockNonce, sgv.Nonce, "Parsed nonce should be zeros")
	assert.Equal(t, mockTag, sgv.Tag, "Parsed tag should be zeros")

	f, w = mustDeserialize(t, sgv.InnerBytes)
	assert.EqualValues(t, 0, w.ttl, "SGV inner TTL should be zero")
	assert.Equal(t, AttributeAlive, f.Attribute, "SGV inner attr")
	require.IsType(t, &PeerSubject{}, f.Subject)
	s = f.Subject.(*PeerSubject)
	assert.Equal(t, mockSubjectKey, s.Key, "SGV inner subject should be correct")
	assert.False(t, f.Expires.After(time.Now()), "SGV inner expires should be <= now")
	assert.IsType(t, &UUIDValue{}, f.Value)
	assert.Equal(t, &UUIDValue{UUID: mockBootID}, f.Value, "SGV inner uuid should be all zeros")
}

func TestParseSignedGroup_Large(t *testing.T) {
	longBytes := make([]byte, 1500)
	n, err := rand.Read(longBytes)
	require.Nil(t, err)
	assert.Equal(t, len(longBytes), n, "Should load random data for full array")
	_, _, p := mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{},
		Expires:   time.Time{},
		Value: &SignedGroupValue{
			InnerBytes: longBytes,
		},
	})
	f, _ := mustDeserialize(t, p)
	require.IsType(t, &SignedGroupValue{}, f.Value)
	assert.Equal(t, longBytes, f.Value.(*SignedGroupValue).InnerBytes)
}
