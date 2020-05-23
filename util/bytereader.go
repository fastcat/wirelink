package util

import "io"

// ByteReader combines io.Reader and io.ByteReader
type ByteReader interface {
	io.Reader
	io.ByteReader
}
