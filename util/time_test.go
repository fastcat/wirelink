package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_TimeMaxVsNow(t *testing.T) {
	timeMax := TimeMax()
	now := time.Now()

	assert.True(t, timeMax.After(now))
	assert.True(t, now.Before(timeMax))
	assert.True(t, now.Sub(timeMax) < 255*time.Second)
	assert.Less(t, int64(now.Sub(timeMax)), int64(255*time.Second))
}
