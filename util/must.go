package util

// MustBytes is a helper, esp. for BinaryMarshaller, that takes a tuple of
// a byte slice and maybe an error and panics if there is an error, or else
// returns the byte slice
func MustBytes(value []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return value
}

// MustByte is a helper, esp. for ByteReader, that takes a tuple of
// a byte and maybe an error and panics if there is an error, or else
// returns the byte
func MustByte(value byte, err error) byte {
	if err != nil {
		panic(err)
	}
	return value
}

// MustInt64 is a helper, esp. for encoding.binary, that takes a tuple of
// an int64 and maybe an error and panics if there is an error, or else
// returns the int64
func MustInt64(value int64, err error) int64 {
	if err != nil {
		panic(err)
	}
	return value
}
