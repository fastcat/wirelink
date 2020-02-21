// Package log is a bit of a ridiculous package to have, but the built in `log` package
// always writes to stderr, and fancy structured logging isn't what this tool needs
package log

import (
	"fmt"
	"os"
	"time"
)

// TODO: copy efficient buffer management from core `log` package

// Info writes a formatted string with an appended newline to Stdout.
// errors are ignored.
func Info(format string, a ...interface{}) {
	if format[len(format)-1] != '\n' {
		format = format + "\n"
	}
	if debugEnabled {
		// format = time.Now().Format(debugStampFormat) + " " + format
		format = debugOffset() + " " + format
	}
	os.Stdout.WriteString(fmt.Sprintf(format, a...))
}

// Error writes a formatted string with an appended newline to Stderr.
// errors are ignored.
func Error(format string, a ...interface{}) {
	if format[len(format)-1] != '\n' {
		format = format + "\n"
	}
	if debugEnabled {
		// format = time.Now().Format(debugStampFormat) + " " + format
		format = debugOffset() + " " + format
	}
	os.Stderr.WriteString(fmt.Sprintf(format, a...))
}

var debugEnabled bool
var debugReference time.Time

// similar to RFC3339
// const debugStampFormat = "2006-01-02T15:04:05.999"

// SetDebug controls whether Debug does anything
func SetDebug(enabled bool) {
	debugEnabled = enabled
	if enabled {
		debugReference = time.Now()
	}
}

func debugOffset() string {
	return time.Now().Sub(debugReference).Round(time.Millisecond).String()
}

// IsDebug returns whether debug logging is enabled
func IsDebug() bool {
	return debugEnabled
}

// Debug writes a formatted string with an appended newline to Stdout, if enabled.
// errors are ignored.
func Debug(format string, a ...interface{}) {
	if !debugEnabled {
		return
	}
	if format[len(format)-1] != '\n' {
		format = format + "\n"
	}
	// format = time.Now().Format(debugStampFormat) + " " + format
	format = debugOffset() + " " + format
	os.Stdout.WriteString(fmt.Sprintf(format, a...))
}
