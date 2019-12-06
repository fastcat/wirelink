package util

// CloneBytes returns a new copy of the input data
func CloneBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	ret := make([]byte, len(data))
	copy(ret, data)
	return ret
}
