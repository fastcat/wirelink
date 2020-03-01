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
	now := time.Now()
	fact1 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   now.Add(30 * time.Second),
		Subject:   &PeerSubject{Key: key},
		Value:     &IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}
	fact2 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   now.Add(31 * time.Second),
		Subject:   &PeerSubject{Key: key},
		Value:     &IPPortValue{IP: net.IPv4(127, 0, 0, 1), Port: 51820},
	}
	fact3 := Fact{
		Attribute: AttributeEndpointV4,
		Expires:   now.Add(32 * time.Second),
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
			// don't be order-sensitive
			assert.Len(t, got, len(tt.want))
			for _, f := range tt.want {
				assert.Contains(t, got, f)
			}
		})
	}
}

func TestSliceHas(t *testing.T) {
	f1 := &Fact{}
	f2 := &Fact{}
	type args struct {
		facts     []*Fact
		predicate func(*Fact) bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"nil",
			args{nil, nil},
			false,
		},
		{
			"empty",
			args{[]*Fact{}, nil},
			false,
		},
		{
			"no match",
			args{[]*Fact{f1, f2}, func(*Fact) bool { return false }},
			false,
		},
		{
			"match",
			args{[]*Fact{f1, f2}, func(f *Fact) bool { return f == f2 }},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SliceHas(tt.args.facts, tt.args.predicate))
		})
	}
}
