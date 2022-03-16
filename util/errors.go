package util

import (
	"fmt"
)

// WrapOrNewf calls fmt.Errorf with varying format depending on whether err is
// nil, always returning an error value
func WrapOrNewf(err error, format string, args ...interface{}) error {
	if err == nil {
		return fmt.Errorf(format, args...)
	}
	args = append(args, err)
	return fmt.Errorf(format+": %w", args...)
}
