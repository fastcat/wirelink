package testutils

import (
	"path"
	"runtime"
)

// SrcDirectory uses the call stack to compute the directory of the caller's source file.
func SrcDirectory() string {
	_, filename, _, _ := runtime.Caller(1)
	return path.Dir(filename)
}
