package util

import "github.com/pkg/errors"

// WrapOrNewf calls errors.Wrapf or errors.Errorf depending on whether err is nil,
// always returning an error value, unlike errors.Wrapf
func WrapOrNewf(err error, format string, args ...interface{}) error {
	if err == nil {
		return errors.Errorf(format, args...)
	}
	return errors.Wrapf(err, format, args...)
}
