//+build !linux

package host

import (
	"errors"

	"github.com/fastcat/wirelink/internal/networking"
)

// CreateHost creates the default Environment implementation for the host OS
func CreateHost() (networking.Environment, error) {
	return nil, errors.New("No network wrapper for this platform")
}
