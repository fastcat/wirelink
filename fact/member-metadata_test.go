package fact

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/fastcat/wirelink/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeLongString(len int) string {
	b := &strings.Builder{}
	b.Grow(len)
	for b.Len() < len {
		if b.Len() == 0 {
			b.WriteString("x")
		} else if b.Len() <= len/2 {
			b.WriteString(b.String())
		} else {
			b.WriteString(makeLongString(len - b.Len()))
		}
	}
	return b.String()
}
func TestMemberMetadata_MarshalBinary(t *testing.T) {
	type fields struct {
		attributes map[MemberAttribute]string
	}
	tests := []struct {
		name   string
		fields fields
		// due to map orderings, need multiple want options sometimes here
		wantOneOf [][]byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"empty",
			fields{map[MemberAttribute]string{}},
			[][]byte{{0}},
			assert.NoError,
		},
		{
			"one attribute, empty value",
			fields{map[MemberAttribute]string{MemberName: ""}},
			[][]byte{{
				2, // content length
				byte(MemberName),
				0, // value length
			}},
			assert.NoError,
		},
		{
			"one attribute, ascii value",
			fields{map[MemberAttribute]string{MemberName: "fred"}},
			[][]byte{{
				6,
				byte(MemberName),
				4,
				'f', 'r', 'e', 'd',
			}},
			assert.NoError,
		},
		{
			"two attributes, ascii values",
			fields{map[MemberAttribute]string{
				MemberName:           "fred",
				MemberAttribute('z'): "foo",
			}},
			[][]byte{
				{
					11,
					byte(MemberName),
					4,
					'f', 'r', 'e', 'd',
					'z',
					3,
					'f', 'o', 'o',
				}, {
					11,
					'z',
					3,
					'f', 'o', 'o',
					byte(MemberName),
					4,
					'f', 'r', 'e', 'd',
				},
			},
			assert.NoError,
		},
		{
			"too much data",
			fields{map[MemberAttribute]string{
				MemberName: makeLongString(128 * 128 * 128),
			}},
			[][]byte{nil},
			// TODO: assert the specific error
			assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := &MemberMetadata{
				attributes: tt.fields.attributes,
			}
			got, err := mm.MarshalBinary()
			tt.assertion(t, err)
			assert.Contains(t, tt.wantOneOf, got)
		})
	}
}

func TestMemberMetadata_DecodeFrom(t *testing.T) {
	type fields struct {
		attributes map[MemberAttribute]string
	}
	tests := []struct {
		name       string
		data       []byte
		wantFields fields
		assertion  assert.ErrorAssertionFunc
	}{
		{
			"empty",
			[]byte{0},
			fields{map[MemberAttribute]string{}},
			assert.NoError,
		},
		{
			"one attribute, empty value",
			[]byte{
				2, // content length
				byte(MemberName),
				0, // value length
			},
			fields{map[MemberAttribute]string{MemberName: ""}},
			assert.NoError,
		},
		{
			"one attribute, ascii value",
			[]byte{
				6,
				byte(MemberName),
				4,
				'f', 'r', 'e', 'd',
			},
			fields{map[MemberAttribute]string{MemberName: "fred"}},
			assert.NoError,
		},
		{
			"two attributes, ascii values",
			[]byte{
				11,
				byte(MemberName),
				4,
				'f', 'r', 'e', 'd',
				'z',
				3,
				'f', 'o', 'o',
			},
			fields{map[MemberAttribute]string{
				MemberName:           "fred",
				MemberAttribute('z'): "foo",
			}},
			assert.NoError,
		},
		// TODO: assert specific errors
		{
			"error decoding empty buffer",
			[]byte{},
			// an empty map would be fine here, nil is a side effect of test initialization
			fields{nil},
			assert.Error,
		},
		{
			"truncated payload mode 1",
			[]byte{16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			fields{nil},
			assert.Error,
		},
		{
			"truncated payload mode 2",
			[]byte{16},
			fields{nil},
			assert.Error,
		},
		{
			"attribute length error",
			[]byte{2, 1, 255},
			fields{map[MemberAttribute]string{}},
			assert.Error,
		},
		{
			"attribute payload overrun",
			[]byte{3, 1, 2, 1},
			fields{map[MemberAttribute]string{}},
			assert.Error,
		},
		// TODO: attribute repeat test with error
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := &MemberMetadata{}
			tt.assertion(t, mm.DecodeFrom(0, bytes.NewBuffer(tt.data)))
			assert.Equal(t, tt.wantFields.attributes, mm.attributes)
		})
	}
}

func TestMemberMetadata_String(t *testing.T) {
	type fields struct {
		attributes map[MemberAttribute]string
	}
	tests := []struct {
		name    string
		fields  fields
		wantOne []string
	}{
		{
			"empty",
			fields{map[MemberAttribute]string{}},
			[]string{"(empty)"},
		},
		{
			"one",
			fields{map[MemberAttribute]string{
				MemberName: "foo",
			}},
			[]string{"n:\"foo\""},
		},
		{
			"binary 0",
			fields{map[MemberAttribute]string{
				MemberIsBasic: string(byte(0)),
			}},
			[]string{"b:\"\\x00\""},
		},
		{
			"binary 1",
			fields{map[MemberAttribute]string{
				MemberIsBasic: string(byte(1)),
			}},
			[]string{"b:\"\\x01\""},
		},
		{
			"many",
			fields{map[MemberAttribute]string{
				MemberName:           "foo",
				MemberAttribute('a'): "bar",
				MemberAttribute('b'): "baz",
			}},
			[]string{
				"n:\"foo\",+2",
				"a:\"bar\",+2",
				"b:\"baz\",+2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := &MemberMetadata{
				attributes: tt.fields.attributes,
			}
			assert.Contains(t, tt.wantOne, mm.String())
		})
	}
}

func TestBuildMemberMetadata(t *testing.T) {
	type args struct {
		name  string
		basic bool
	}
	tests := []struct {
		name string
		args args
		want *MemberMetadata
	}{
		{
			"named and not basic",
			args{"foo", false},
			&MemberMetadata{map[MemberAttribute]string{
				MemberName:    "foo",
				MemberIsBasic: string([]byte{0}),
			}},
		},
		{
			"named and basic",
			args{"foo", true},
			&MemberMetadata{map[MemberAttribute]string{
				MemberName:    "foo",
				MemberIsBasic: string([]byte{1}),
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, BuildMemberMetadata(tt.args.name, tt.args.basic))
		})
	}
}

func TestMemberMetadata_Equality(t *testing.T) {
	// repeat this a bunch because hashes are unpredictable
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("foo%d", i)
		basic := i%2 == 0
		mm1 := BuildMemberMetadata(name, basic)
		mm2 := BuildMemberMetadata(name, basic)

		require.Equal(t, mm1, mm2)

		b1 := util.MustBytes(mm1.MarshalBinary())
		b2 := util.MustBytes(mm2.MarshalBinary())

		require.Equal(t, b1, b2)

		// this doesn't work
		// assert.True(t, mm1 == mm2)
	}
}
