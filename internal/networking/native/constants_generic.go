//go:build !linux && !darwin && !windows
// +build !linux,!darwin,!windows

package native

// this is probably wrong
const localhostInterfaceName = "lo"
