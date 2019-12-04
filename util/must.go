package util

// MustBytes is a helper, esp. for BinaryMarshaller, that takes a tuple of a
// byte slice and maybe an error and panics if there is an error, or else
// returns the byte slice
func MustBytes(value []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return value
}
