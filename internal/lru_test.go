package internal

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLRUMap_trim(t *testing.T) {
	type op struct {
		get  bool
		k, v int
	}
	type em = map[int]lruItem[int]
	type expected struct {
		n int32
		m em
	}
	tests := []struct {
		name     string
		ratio    int
		ops      []op
		expected expected
	}{
		{
			"load",
			1,
			[]op{
				{false, 0, 10},
				{false, 1, 11},
				{false, 2, 12},
			},
			expected{3, em{0: {10, 1}, 1: {11, 2}, 2: {12, 3}}},
		},
		{
			"trim once",
			2,
			[]op{
				{false, 0, 10},
				{false, 1, 11},
				{false, 2, 12},
				{true, 1, 11},
				{true, 2, 12},
				{true, 1, 11},
				{true, 2, 12},
				{false, 1, 11},
			},
			expected{6, em{1: {11, 6}, 2: {12, 5}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewLRUMap[int, int](0, tt.ratio)
			for i, o := range tt.ops {
				if o.get {
					v, ok := m.Get(o.k)
					if assert.True(t, ok, "op[%d]: get[%d] ok", i, o.k) {
						assert.Equal(t, o.v, v, "op[%d]: get[%d]", i, o.k)
					}
				} else {
					m.Set(o.k, o.v)
				}
				// this assertion is wrong if we have trimmed
				// assert.Equal(t, int32(i+1), m.n, "op[%d]: m.n after", i)
			}
			assert.Equal(t, tt.expected.n, m.n)
			assert.Len(t, m.m, len(tt.expected.m))
			for k, v := range tt.expected.m {
				i, ok := m.m[k]
				if assert.True(t, ok, "map has %d", k) {
					assert.Equal(t, v, *i, "map[%d] is correct", k)
				}
			}
		})
	}
}

func TestLRUMap_bounds_random(t *testing.T) {
	// make sure the LRUMap stays confined under the expected usage patterns
	m := NewLRUMap[int, int](10, 2)
	count := 10000
	if testing.Short() {
		count /= 10
	}
	for i := 0; i < count; i++ {
		var k int
		if i == 0 || rand.Intn(5) == 0 {
			k = i
			m.Set(i, 0)
		} else {
			for t := 0; t < 10; t++ {
				k = i - rand.Intn(10)
				if _, ok := m.Get(k); ok {
					break
				}
			}
		}
		// TODO: with trim on get we should be able to narrow this bound down to
		// around 15 or so
		assert.Less(t, len(m.m), 25, "size after %d iterations", i+1)
		// t.Logf("after %d size=%d k=%d", i+1, len(m.m), k)
	}
}
