package fact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemberMetadata_MarshalBinary(t *testing.T) {
	type fields struct {
		attributes map[MemberAttribute]string
	}
	tests := []struct {
		name      string
		fields    fields
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{
			"empty",
			fields{map[MemberAttribute]string{}},
			[]byte{0},
			assert.NoError,
		},
		{
			"one attribute, empty value",
			fields{map[MemberAttribute]string{MemberName: ""}},
			[]byte{
				2, // content length
				byte(MemberName),
				0, // value length
			},
			assert.NoError,
		},
		{
			"one attribute, ascii value",
			fields{map[MemberAttribute]string{MemberName: "fred"}},
			[]byte{
				6,
				byte(MemberName),
				4,
				'f', 'r', 'e', 'd',
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
			assert.Equal(t, tt.want, got)
		})
	}
}
