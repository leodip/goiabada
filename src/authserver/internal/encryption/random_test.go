package encryption

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader stands in for a CSPRNG that cannot be read.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRandomKey(t *testing.T) {
	t.Run("returns the requested number of bytes", func(t *testing.T) {
		for _, n := range []int{64, 32} {
			key, err := RandomKey(n)
			require.NoError(t, err)
			assert.Len(t, key, n)
		}
	})

	t.Run("two calls do not return the same key", func(t *testing.T) {
		first, err := RandomKey(32)
		require.NoError(t, err)
		second, err := RandomKey(32)
		require.NoError(t, err)
		assert.NotEqual(t, first, second)
	})

	t.Run("a failing reader is an error and never a short key", func(t *testing.T) {
		original := randReader
		t.Cleanup(func() { randReader = original })
		randReader = failingReader{}

		key, err := RandomKey(64)
		require.Error(t, err)
		assert.Nil(t, key)
	})
}
