package fact

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseSignedGroup_Trivial(t *testing.T) {
	// trivial test: inner is one empty fact
	// crypto here is all empty

	// lazy way to test against all zeros
	var emptyKey wgtypes.Key
	var emptyNonce [chacha20poly1305.NonceSizeX]byte
	var emptyTag [poly1305.TagSize]byte

	f, w, p := mustEmptyPacket(t)

	f, w, p = mustSerialize(t, &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{},
		Expires:   time.Time{},
		Value: &SignedGroupValue{
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
	assert.Equal(t, emptyKey, s.Key, "parsed subject should be zeros")
	assert.False(t, f.Expires.After(time.Now()), "Parsed expires should be <= now")

	require.IsType(t, &SignedGroupValue{}, f.Value)
	sgv := f.Value.(*SignedGroupValue)
	assert.Equal(t, emptyNonce, sgv.Nonce, "Parsed nonce should be zeros")
	assert.Equal(t, emptyTag, sgv.Tag, "Parsed tag should be zeros")

	f, w = mustDeserialize(t, sgv.InnerBytes)
	assert.EqualValues(t, 0, w.ttl, "SGV inner TTL should be zero")
	assert.Equal(t, AttributeUnknown, f.Attribute, "SGV inner attr")
	require.IsType(t, &PeerSubject{}, f.Subject)
	s = f.Subject.(*PeerSubject)
	assert.Equal(t, emptyKey, s.Key, "SGV inner subject should be zeros")
	assert.False(t, f.Expires.After(time.Now()), "SGV inner expires should be <= now")
	require.IsType(t, EmptyValue{}, f.Value)
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
