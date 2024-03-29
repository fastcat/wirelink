//go:build linux
// +build linux

package host

import (
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/linux"
)

// CreateHost creates the default Environment implementation for the host OS
func CreateHost() (networking.Environment, error) {
	return linux.CreateLinux()
}
