package fact

import (
	"sort"
	"time"

	"github.com/fastcat/wirelink/util"
)

// Key is a comparable version of the subject, attribute, and value of a Fact
type Key struct {
	// Attribute is a byte, nothing to worry about in comparisons
	Attribute Attribute
	// subject/value are likely to contain slices which are not comparable in a useful sense
	// so instead convert to bytes and then coerce that to a "string"
	subject string
	value   string
}

// KeyOf returns the FactKey for a Fact
func KeyOf(fact *Fact) Key {
	valueBytes := util.MustBytes(fact.Value.MarshalBinary())
	// special case: for Alive, we ignore the value!
	if fact.Attribute == AttributeAlive {
		valueBytes = []byte{}
	}
	return Key{
		Attribute: fact.Attribute,
		subject:   string(util.MustBytes(fact.Subject.MarshalBinary())),
		value:     string(valueBytes),
	}
}

// factSet is used to map fact keys to the "best" fact for that key
type factSet map[Key]*Fact

/*
func (s factSet) has(fact *Fact) bool {
	_, ret := s[KeyOf((fact))]
	return ret
}
*/

func (s factSet) upsert(fact *Fact) time.Time {
	key := KeyOf(fact)

	best, ok := s[key]
	if !ok || best.Expires.Before(fact.Expires) {
		best = fact
		s[key] = best
	}
	return best.Expires
}

/*
func (s factSet) delete(fact *Fact) {
	delete(s, KeyOf(fact))
}
*/

func setOf(facts []*Fact) factSet {
	s := make(factSet)
	for _, f := range facts {
		s.upsert(f)
	}
	return s
}

// MergeList merges duplicate facts in a slice, keeping the latest Expires value
func MergeList(facts []*Fact) []*Fact {
	s := setOf(facts)
	ret := make([]*Fact, 0, len(s))
	for _, fact := range s {
		ret = append(ret, fact)
	}
	return ret
}

// SortedCopy makes a copy of the list and then sorts it "naturally"
func SortedCopy(facts []*Fact) []*Fact {
	sorted := make([]*Fact, len(facts))
	copy(sorted, facts)
	sort.Slice(sorted, func(i, j int) bool {
		l, r := sorted[i], sorted[j]
		if l.Subject.String() < r.Subject.String() {
			return true
		} else if l.Subject.String() > r.Subject.String() {
			return false
		} else if l.Attribute < r.Attribute {
			return true
		} else if l.Attribute > r.Attribute {
			return false
		} else if l.Value.String() < r.Value.String() {
			return true
		} else if l.Value.String() > r.Value.String() {
			return false
		} else {
			return l.Expires.Before(r.Expires)
		}
	})
	return sorted
}

// SliceHas returns true if and only if predicate returns true for a fact in the
// given slice
func SliceHas(facts []*Fact, predicate func(*Fact) bool) bool {
	return SliceIndexOf(facts, predicate) >= 0
}

// SliceIndexOf returns the index of the first element in the slice for which
// the predicate returns true, or -1 if there is no match or the slice is empty
func SliceIndexOf(facts []*Fact, predicate func(*Fact) bool) int {
	for i, f := range facts {
		if predicate(f) {
			return i
		}
	}
	return -1
}

// KeysDifference computes the fact keys that are different between two slices
func KeysDifference(old, new []*Fact) (onlyOld, onlyNew []Key) {
	oldSet := setOf(old)
	newSet := setOf(new)

	for k := range oldSet {
		if _, ok := newSet[k]; !ok {
			onlyOld = append(onlyOld, k)
		}
	}
	for k := range newSet {
		if _, ok := oldSet[k]; !ok {
			onlyOld = append(onlyNew, k)
		}
	}

	return
}
