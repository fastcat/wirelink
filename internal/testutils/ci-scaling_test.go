package testutils

import (
	"testing"
	"time"
)

func Test_measurePerf(t *testing.T) {
	for c := 1; c <= 1000; c *= 10 {
		x := measurePerf(time.Millisecond * time.Duration(c))
		t.Logf("%d ms: %d", c, x)
	}
}
