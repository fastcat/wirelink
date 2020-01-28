package fact

import (
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestFactKeyEquality(t *testing.T) {
	key := testutils.MustKey(t)

	fact1 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Now().Add(30 * time.Second),
		Subject:   &PeerSubject{Key: key},
		Value:     &IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}
	fact2 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Now().Add(30 * time.Second),
		Subject:   &PeerSubject{Key: key},
		Value:     &IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}

	factKey1 := KeyOf(&fact1)
	factKey2 := KeyOf(&fact2)

	assert.Exactly(t, factKey1, factKey2, "Keys for same fact should be equal")
}

func TestMergeList(t *testing.T) {
	key := testutils.MustKey(t)
	fact1 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Now().Add(30 * time.Second),
		Subject:   &PeerSubject{Key: key},
		Value:     &IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}
	fact2 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Now().Add(31 * time.Second),
		Subject:   &PeerSubject{Key: key},
		Value:     &IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}
	fact3 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   time.Now().Add(32 * time.Second),
		Subject:   &PeerSubject{Key: key},
		Value:     &IPPortValue{IP: net.IPv4(127, 0, 0, 2), Port: 51820},
	}

	type args struct {
		facts []*Fact
	}
	tests := []struct {
		name string
		args args
		want []*Fact
	}{
		{
			"simple sameness",
			args{[]*Fact{&fact1, &fact2}},
			[]*Fact{&fact2},
		},
		{
			"simple difference",
			args{[]*Fact{&fact1, &fact2, &fact3}},
			[]*Fact{&fact2, &fact3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeList(tt.args.facts)
			assert.Equal(t, tt.want, got, "MergeList()")
		})
	}
}
