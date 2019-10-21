package util

import "time"

// TimeMax is the maximum representable time in go.
// see: https://stackoverflow.com/a/32620397/7649
// see also `time.go` in the runtime
func TimeMax() time.Time {
	return time.Unix(1<<63-62135596801, 999999999)
}
