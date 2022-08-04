package testutils

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// CaptureOutput runs f with os.Stdout redirected to a temp file,
// and then re-reads everything that is written and returns it
func CaptureOutput(t *testing.T, f func()) []byte {
	originalOutput := os.Stdout

	tempfile, err := os.CreateTemp(t.TempDir(), "wirelink-test-output-capture")
	require.NoError(t, err)
	defer os.Remove(tempfile.Name())

	func() {
		os.Stdout = tempfile
		defer func() { os.Stdout = originalOutput }()
		f()
	}()

	_, err = tempfile.Seek(0, 0)
	require.NoError(t, err)
	data, err := io.ReadAll(tempfile)
	require.NoError(t, err)

	return data
}
