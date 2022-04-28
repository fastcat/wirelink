package internal

import (
	"sync"
	"sync/atomic"
)

type lruItem[V any] struct {
	v V
	n int32
}

// LRUMap wraps a Map with a crude LRU system. It works by tracking a top level
// counter (`n`) that is incremented for every Get and Set, and the new counter
// value stored with each item as well. After a Set, `trim` may be invoked. The
// `trim` operation constrains the map size by computing a threshold value for
// the counter `n` and deleting any entry whose last access is below that
// threshold. The threshold is determined as a `ratio` times the number of map
// items, providing a crude heuristic of removing items not accessed in the last
// `ratio` passes through the full map. As such, the LRUMap does _not_ defend
// against degenerate use cases where new items are often Set but rarely or
// never Get, but it will systematically prune items that are rarely accessed,
// with `ratio` determining what "rare" means.
type LRUMap[K comparable, V any] struct {
	mu    sync.RWMutex
	m     map[K]*lruItem[V]
	ratio int
	n     int32
}

// NewLRUMap creates a new LRUMap with the given initial map allocation size and
// trim ratio
func NewLRUMap[K comparable, V any](size, ratio int) *LRUMap[K, V] {
	return &LRUMap[K, V]{m: make(map[K]*lruItem[V], size), ratio: ratio}
}

// trim removes excess items from the map based on LRU data. It must be called
// with mu Lock()ed.
//
// trim works by computing a "threshold" value as n - len*ratio. If the
// threshold is negative, trim does nothing.
//
// Otherwise any map item whose last n value is less than the threshold is
// deleted.
//
// The n value of any items not deleted, and the top level n value, are
// decremented by the threshold so that the "trim due" condition is reset.
func (m *LRUMap[K, V]) trim() {
	t := atomic.LoadInt32(&m.n) - int32(len(m.m)*m.ratio)
	if t < 0 {
		return
	}
	for k, v := range m.m {
		if vn := atomic.LoadInt32(&v.n); vn < t {
			delete(m.m, k)
		} else {
			atomic.AddInt32(&v.n, -t)
		}
	}
	atomic.AddInt32(&m.n, -t)
}

func (m *LRUMap[K, V]) Get(k K) (v V, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	i := m.m[k]
	if i == nil {
		return
	}
	atomic.StoreInt32(&i.n, atomic.AddInt32(&m.n, 1))
	return i.v, true
}

func (m *LRUMap[K, V]) Set(k K, v V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	nn := atomic.AddInt32(&m.n, 1)
	var i *lruItem[V]
	if i = m.m[k]; i != nil {
		i.v = v
		atomic.StoreInt32(&i.n, nn)
	} else {
		i = &lruItem[V]{v, nn}
		m.m[k] = i
		if int(nn) > len(m.m)*m.ratio {
			m.trim()
		}
	}
}

// Memoize uses an LRUMap to memoize the given function.
func Memoize[K comparable, V any](size, ratio int, f func(K) V) func(K) V {
	m := NewLRUMap[K, V](size, ratio)
	return func(k K) V {
		if v, ok := m.Get(k); ok {
			return v
		}
		v := f(k)
		m.Set(k, v)
		return v
	}
}
