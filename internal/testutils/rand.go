package testutils

import (
	"fmt"
	"math/rand"
	"time"
)

// make sure tests are really random
func init() {
	seed := time.Now().UnixNano()
	fmt.Printf("Today's seed is %v\n", seed)
	Rand = rand.New(rand.NewSource(seed))
}

// Rand is a per-run initialized non-crypto RNG
var Rand *rand.Rand
