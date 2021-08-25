package testutils

import (
	"math"
	"os"
	"runtime"
	"time"
)

// this file has runtime-computed constants to compensate for poor performance
// of CI VMs compared to dedicated developer systems, when running performance
// tests

// empirical measure on the slowest system tested that passes tests
const baseline = 1_000_000_000

// CIScaleFactor is an approximate scaling factor by which to multiply time
// deadlines in performance-sensitive tests to compensate for the running system
// being slower than the reference system.
var CIScaleFactor int

// CIScaleFactorDuration is just CIScaleFactor cast to a time.Duration for
// simplicity.
var CIScaleFactorDuration time.Duration

func measurePerf(target time.Duration) int {
	counter := 0
	start := time.Now()
	deadline := start.Add(target)
	now := start
	for ; now.Before(deadline); now = time.Now() {
		for i := 0; i < 1000; i++ {
			counter += i
		}
	}

	return int(float64(counter) * float64(target) / float64(now.Sub(start)))
}

func init() {
	CIScaleFactor = 1
	// macOS runners seem to be super slow, try to compensate with a
	// micro-benchmark to compare vs. a reference system
	if runtime.GOOS == "darwin" && os.Getenv("CI") != "" {
		thisMachine := measurePerf(time.Millisecond)
		if thisMachine >= baseline {
			CIScaleFactor = 1
		} else {
			CIScaleFactor = int(math.Ceil(float64(baseline) / float64(thisMachine)))
		}
	}
	CIScaleFactorDuration = time.Duration(CIScaleFactor)
}
