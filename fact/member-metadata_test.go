package fact

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		// TODO: encoding error tests
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
