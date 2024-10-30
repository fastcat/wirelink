package internal

import (
	"github.com/hashicorp/golang-lru/arc/v2"
)

// Memoize uses a cache to memoize the given function.
func Memoize[K comparable, V any](size int, f func(K) V) func(K) V {
	m, err := arc.NewARC[K, V](size)
	if err != nil {
		panic(err)
	}

	return func(k K) V {
		if v, ok := m.Get(k); ok {
			return v
		}
		v := f(k)
		m.Add(k, v)
		return v
	}
}
