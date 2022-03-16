package util

import (
	"bytes"
	"encoding"
	"fmt"
	"io"
)

// Decodable is an interface that mimics BinaryUnmarshaller, but sources from
// an io.Reader instead of a slice
type Decodable interface {
	// DecodeFrom reads just enough bytes from the reader to deserialize itself
	DecodeFrom(lengthHint int, reader io.Reader) error
}

// DecodeFrom provides an equivalent function to Decodable.DecodeFrom, but for
// types that implement BinaryUnmarshaler and which have a fixed known length,
// e.g. to provide a default implementation for Decodable for such types
func DecodeFrom(value encoding.BinaryUnmarshaler, readLen int, reader io.Reader) error {
	var data []byte
	switch r := reader.(type) {
	case *bytes.Buffer:
		data = r.Next(readLen)
		if len(data) != readLen {
			return fmt.Errorf("unable to read %T: only %d of %d bytes available", value, readLen, len(data))
		}
	default:
		data = make([]byte, readLen)
		n, err := io.ReadFull(r, data)
		if err != nil {
			return fmt.Errorf("unable to read %T (read %d of %d bytes): %w", value, n, readLen, err)
		}
	}
	err := value.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("unable to read %T: unmarshal failed: %w", value, err)
	}
	return nil
}
