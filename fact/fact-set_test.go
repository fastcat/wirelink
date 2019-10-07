package fact

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestFactKeyEquality(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal("Unable to generate a private key")
	}
	key = key.PublicKey()

	fact1 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Now().Add(30 * time.Second),
		Subject:   PeerSubject{Key: key},
		Value:     IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}
	fact2 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Now().Add(30 * time.Second),
		Subject:   PeerSubject{Key: key},
		Value:     IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}

	fkey1 := KeyOf(&fact1)
	fkey2 := KeyOf(&fact2)

	if fkey1 != fkey2 {
		t.Errorf("Keys for same facts are unequal: %v, %v", fkey1, fkey2)
	}
}
