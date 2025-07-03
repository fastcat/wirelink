package fact

import "time"

// timeScale is the quantum of measurement for serializing and parsing facts onto the wire.
// It is only present as a mutable parameter for use in tests where we want to run scenarios
// faster than normal realtime would permit. Changing this on a live service is a breaking
// change to the wire protocol.
const timeScale = time.Second
