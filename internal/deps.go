// this file never builds, it just exists to keep tools we need for code
// generation present in go.mod

// +build never

package internal

import (
	_ "github.com/vektra/mockery"
)
