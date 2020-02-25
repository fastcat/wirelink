package util

import (
	"testing"

	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stringPtr(value string) *string {
	return &value
}

func TestWrapOrNewf(t *testing.T) {
	type args struct {
		err    error
		format string
		args   []interface{}
	}
	tests := []struct {
		name       string
		args       args
		wantError  string
		wantUnwrap *string
	}{
		{
			"not wrapping",
			args{
				nil,
				"not wrapping",
				nil,
			},
			"not wrapping",
			nil,
		},
		{
			"simple wrapping",
			args{
				errors.New("inner"),
				"simple wrapping",
				nil,
			},
			"simple wrapping: inner",
			stringPtr("inner"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WrapOrNewf(tt.args.err, tt.args.format, tt.args.args...)
			require.NotNil(t, err)
			assert.Equal(t, tt.wantError, err.Error())
			cause := errors.Unwrap(err)
			// there may be multiple layers, dig and find the bottom
			for next := errors.Unwrap(cause); next != nil; next = errors.Unwrap(cause) {
				cause = next
			}
			if tt.wantUnwrap == nil {
				assert.Nil(t, cause)
			} else {
				require.NotNil(t, cause)
				assert.Equal(t, *tt.wantUnwrap, cause.Error())
			}
		})
	}
}
