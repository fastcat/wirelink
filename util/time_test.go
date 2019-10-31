package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_TimeMaxVsNow(t *testing.T) {
	tmax := TimeMax()
	now := time.Now()

	assert.True(t, tmax.After(now))
	assert.True(t, now.Before(tmax))
	assert.True(t, now.Sub(tmax) < 255*time.Second)
	assert.Less(t, int64(now.Sub(tmax)), int64(255*time.Second))
}
