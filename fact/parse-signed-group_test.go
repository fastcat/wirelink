package fact

import (
	"testing"
	"time"

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

	f := &Fact{
		Attribute: AttributeUnknown,
		Subject:   &PeerSubject{},
		Expires:   time.Time{},
		Value:     EmptyValue{},
	}
	w, err := f.ToWire()
	if err != nil {
		t.Fatal("Unable to wire format empty fact")
	}
	p, err := w.Serialize()
	if err != nil {
		t.Fatal("Unable to serialize empty fact")
	}

	f = &Fact{
		Attribute: AttributeSignedGroup,
		Subject:   &PeerSubject{},
		Expires:   time.Time{},
		Value: &SignedGroupValue{
			InnerBytes: p,
		},
	}
	w, err = f.ToWire()
	if err != nil {
		t.Fatal("Unable to wire format signed group")
	}
	if w.ttl != 0 {
		t.Errorf("Wire TTL is %d, not 0", w.ttl)
	}
	p, err = w.Serialize()
	if err != nil {
		t.Fatal("Unable to serialize signed group")
	}

	w, err = Deserialize(p)
	if err != nil {
		t.Fatal("Unable to deserialize signed group")
	}
	if w.ttl != 0 {
		t.Errorf("Deserialized TTL is %d, not 0", w.ttl)
	}
	f, err = Parse(w)
	if err != nil {
		t.Fatal("Unable to parse signed group")
	}

	if f.Attribute != AttributeSignedGroup {
		t.Errorf("Parsed attr is %d not %d", f.Attribute, AttributeSignedGroup)
	}
	s, ok := f.Subject.(*PeerSubject)
	if !ok {
		t.Errorf("Parsed subject is a %T, not a *PeerSubject", f.Subject)
	} else if s.Key != emptyKey {
		t.Errorf("Parsed subject is non-zero: %v", s.Key)
	}
	if f.Expires.After(time.Now()) {
		t.Errorf("Parsed expires should be <= now: %v", f.Expires)
	}
	sgv, ok := f.Value.(*SignedGroupValue)
	if !ok {
		t.Fatalf("Parsed value is a %T, not a *SignedGroupValue", f.Value)
	}
	if sgv.Nonce != emptyNonce {
		t.Errorf("Parsed nonce is non-zero: %v", sgv.Nonce)
	}
	if sgv.Tag != emptyTag {
		t.Errorf("Parsed tag is non-zero: %v", sgv.Tag)
	}

	w, err = Deserialize(sgv.InnerBytes)
	if err != nil {
		t.Fatalf("Unable to deserialize SGV inner: %v", err)
	}
	if w.ttl != 0 {
		t.Errorf("SGV inner TTL is %d, not 0", w.ttl)
	}
	f, err = Parse(w)
	if err != nil {
		t.Fatalf("Unable to parse SGV inner: %v", err)
	}

	if f.Attribute != AttributeUnknown {
		t.Errorf("SGV inner attr is %d, not %d", f.Attribute, AttributeUnknown)
	}
	s, ok = f.Subject.(*PeerSubject)
	if !ok {
		t.Errorf("SGV inner subject is a %T, not a *PeerSubject", f.Subject)
	} else if s.Key != emptyKey {
		t.Errorf("SGV inner subject is non-zero: %v", s.Key)
	}
	if f.Expires.After(time.Now()) {
		t.Errorf("SGV inner expires should be <= now: %v", f.Expires)
	}
	_, ok = f.Value.(EmptyValue)
	if !ok {
		t.Errorf("SGV inner value is a %T, not an EmptyValue", f.Value)
	}
}
