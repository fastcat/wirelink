// Package log is a bit of a ridiculous package to have, but the built in `log` package
// always writes to stderr, and fancy structured logging isn't wnat this tool needs
package log

import (
	"fmt"
	"os"
)

// TODO: copy efficient buffer management from core `log` package

// Info writes a formatted string with an appended newline to Stdout.
// errors are ignored.
func Info(format string, a ...interface{}) {
	if format[len(format)-1] != '\n' {
		format = format + "\n"
	}
	os.Stdout.WriteString(fmt.Sprintf(format, a...))
}

// Error write sa formatted string with an appended newline to Stderr.
// errors are ignored.
func Error(format string, a ...interface{}) {
	if format[len(format)-1] != '\n' {
		format = format + "\n"
	}
	os.Stderr.WriteString(fmt.Sprintf(format, a...))
}
