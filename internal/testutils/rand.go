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
	rand.Seed(seed)
}
