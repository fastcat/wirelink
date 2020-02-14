package testutils

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// CaptureOutput runs f with os.Stdout redirected to a temp file,
// and then re-reads everything that is written and returns it
func CaptureOutput(t *testing.T, f func()) []byte {
	originalOutput := os.Stdout

	tempfile, err := ioutil.TempFile("", "wirelink-test-output-capture")
	require.NoError(t, err)

	func() {
		os.Stdout = tempfile
		defer func() { os.Stdout = originalOutput }()
		f()
	}()

	tempfile.Seek(0, 0)
	data, err := ioutil.ReadAll(tempfile)
	require.NoError(t, err)

	return data
}
