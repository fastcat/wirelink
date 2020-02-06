package testutils

import "github.com/fastcat/wirelink/log"

// assume that if the testutils package is imported, we're running a test,
// and so should enable debug logging
func init() {
	log.SetDebug(true)
	log.Debug("Auto-enabled debug logging for test mode")
}
