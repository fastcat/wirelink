package fact

import "time"

// timeScale is the quantum of measurement for serializing and parsing facts onto the wire.
// It is only present as a mutable parameter for use in tests where we want to run scenarios
// faster than normal realtime would permit. Changing this on a live service is a breaking
// change to the wire protocol.
var timeScale time.Duration = time.Second

// ScaleExpirationQuantumForTests reconfigures how the fact TTL is represented on the wire to permit
// faster than normal tests
func ScaleExpirationQuantumForTests(factor uint) {
	if factor < 1 || factor > 1000 {
		panic("Test time scale must be in the range [1, 1000]")
	}
	timeScale = time.Second / time.Duration(factor)
}
