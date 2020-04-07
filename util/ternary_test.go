package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTernary(t *testing.T) {
	type args struct {
		value       bool
		trueResult  interface{}
		falseResult interface{}
	}
	tests := []struct {
		name string
		args args
		want interface{}
	}{
		{
			"true",
			args{true, true, false},
			true,
		},
		{
			"false",
			args{false, true, false},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Ternary(tt.args.value, tt.args.trueResult, tt.args.falseResult))
		})
	}
}
