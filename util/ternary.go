package util

// Ternary turns a trivial if/else into a function call
func Ternary(value bool, trueResult, falseResult interface{}) interface{} {
	if value {
		return trueResult
	}
	return falseResult
}
