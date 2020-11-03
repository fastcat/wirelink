package fact

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/fastcat/wirelink/internal/testutils"
	"github.com/google/uuid"
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

func TestKey_String(t *testing.T) {
	type fields struct {
		Attribute Attribute
		subject   string
		value     string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			"zeros",
			fields{
				Attribute: AttributeUnknown,
				subject:   "",
				value:     "",
			},
			`[a:'\x00' s:"" v:""]`,
		},
		{
			"real",
			fields{
				Attribute: AttributeMember,
				subject: string([]byte{
					0xe4, 0x25, 0x0c, 0xb1, 0xc9, 0x4b, 0xcd, 0x4e, 0xeb, 0x4e, 0x09, 0x06, 0xab, 0x81, 0x8a, 0x3a,
					0x8c, 0x05, 0xe2, 0x3c, 0xfd, 0x6e, 0x38, 0x4f, 0xca, 0x8d, 0x5b, 0x73, 0xef, 0xb1, 0x0b, 0x18,
				}),
				value: "",
			},
			`[a:m s:5CUMsclLzU7rTgkGq4GKOowF4jz9bjhPyo1bc++xCxg= v:<empty>]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &Key{
				Attribute: tt.fields.Attribute,
				subject:   tt.fields.subject,
				value:     tt.fields.value,
			}
			// check that String works properly both on pointer and value and
			// slice-of-pointer and slice-of-value
			assert.Equal(t, tt.want, k.String())
			assert.Equal(t, tt.want, fmt.Sprintf("%v", k))
			kk := *k
			assert.Equal(t, tt.want, kk.String())
			assert.Equal(t, tt.want, fmt.Sprintf("%v", kk))
			ks := []*Key{k}
			assert.Equal(t, "["+tt.want+"]", fmt.Sprintf("%v", ks))
			kks := []Key{kk}
			assert.Equal(t, "["+tt.want+"]", fmt.Sprintf("%v", kks))
		})
	}
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

func TestKeysDifference(t *testing.T) {
	k1 := testutils.MustKey(t)
	k2 := testutils.MustKey(t)
	k3 := testutils.MustKey(t)
	boot1 := uuid.New()
	boot2 := uuid.New()
	boot3 := uuid.New()

	type args struct {
		old []*Fact
		new []*Fact
	}
	tests := []struct {
		name        string
		args        args
		wantOnlyOld []Key
		wantOnlyNew []Key
	}{
		{
			"empty",
			args{nil, nil},
			nil, nil,
		},
		{
			"all new",
			args{
				nil,
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k1},
						Value:     &UUIDValue{boot1},
					},
				},
			},
			nil,
			[]Key{KeyOf(&Fact{
				Attribute: AttributeAlive,
				Subject:   &PeerSubject{k1},
				Value:     &UUIDValue{boot1},
			})},
		},
		{
			"all old",
			args{
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k1},
						Value:     &UUIDValue{boot1},
					},
				},
				nil,
			},
			[]Key{KeyOf(&Fact{
				Attribute: AttributeAlive,
				Subject:   &PeerSubject{k1},
				Value:     &UUIDValue{boot1},
			})},
			nil,
		},
		{
			"all same",
			args{
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k1},
						Value:     &UUIDValue{boot1},
					},
				},
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k1},
						Value:     &UUIDValue{boot1},
					},
				},
			},
			nil,
			nil,
		},
		{
			"all different",
			args{
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k1},
						Value:     &UUIDValue{boot1},
					},
				},
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k2},
						Value:     &UUIDValue{boot2},
					},
				},
			},
			[]Key{KeyOf(&Fact{
				Attribute: AttributeAlive,
				Subject:   &PeerSubject{k1},
				Value:     &UUIDValue{boot1},
			})},
			[]Key{KeyOf(&Fact{
				Attribute: AttributeAlive,
				Subject:   &PeerSubject{k2},
				Value:     &UUIDValue{boot2},
			})},
		},
		{
			"overlap",
			args{
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k1},
						Value:     &UUIDValue{boot1},
					},
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k2},
						Value:     &UUIDValue{boot2},
					},
				},
				[]*Fact{
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k2},
						Value:     &UUIDValue{boot2},
					},
					{
						Attribute: AttributeAlive,
						Subject:   &PeerSubject{k3},
						Value:     &UUIDValue{boot3},
					},
				},
			},
			[]Key{KeyOf(&Fact{
				Attribute: AttributeAlive,
				Subject:   &PeerSubject{k1},
				Value:     &UUIDValue{boot1},
			})},
			[]Key{KeyOf(&Fact{
				Attribute: AttributeAlive,
				Subject:   &PeerSubject{k3},
				Value:     &UUIDValue{boot3},
			})},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOnlyOld, gotOnlyNew := KeysDifference(tt.args.old, tt.args.new)
			assert.Equal(t, tt.wantOnlyOld, gotOnlyOld)
			assert.Equal(t, tt.wantOnlyNew, gotOnlyNew)
		})
	}
}
