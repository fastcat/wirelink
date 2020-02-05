package util

import (
	"errors"
	"strings"
)

// NetClosingErrorString is the voodoo string returned when you try to use a
// Close()d network connection, because https://github.com/golang/go/issues/4373
const NetClosingErrorString = "use of closed network connection"

// IsNetClosing checks err and its Unwrap chain for NetClosingErrorString
func IsNetClosing(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), NetClosingErrorString) {
		return true
	}
	return IsNetClosing(errors.Unwrap(err))
}
