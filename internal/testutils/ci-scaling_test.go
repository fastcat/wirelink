package testutils

import (
	"testing"
	"time"
)

func Test_measurePerf(t *testing.T) {

	for c := 1; c <= 1000; c *= 10 {
		x := measurePerf(time.Millisecond * time.Duration(c))
		f := float64(c) * float64(baseline) / float64(x)
		t.Logf("%d ms: %d = *%.1f", c, x, f)
		if x/c > baseline {
			t.Logf(" recommend increasing baseline to %d", x/c)
		}
	}
}
