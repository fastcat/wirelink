//+build darwin

package host

import (
	"github.com/fastcat/wirelink/internal/networking"
	"github.com/fastcat/wirelink/internal/networking/darwin"
)

// CreateHost creates the default Environment implementation for the host OS
func CreateHost() (networking.Environment, error) {
	return darwin.CreateDarwin()
}
