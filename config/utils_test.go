package config

import (
	"math/rand"
)

func letter() rune {
	return 'a' + int32(rand.Intn(26))
}

func boolean() bool {
	return rand.Intn(2) == 1
}
