// Package host provides a generic accessor factory to create the appropriate
// platform-specific interface to the host networking APIs.
package host

import "github.com/fastcat/wirelink/internal/networking"

// MustCreateHost calls CreateHost and panics if it fails
func MustCreateHost() networking.Environment {
	env, err := CreateHost()
	if err != nil {
		panic(err)
	}
	return env
}
