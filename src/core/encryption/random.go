package encryption

import (
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

// randReader is crypto/rand in production. It is a variable so a test can make the
// CSPRNG fail, which is the one failure a key generator must not paper over. The
// session store's own newSessionId reads the CSPRNG through exactly this shape, and
// this copies it rather than inventing a second one.
var randReader io.Reader = rand.Reader

// RandomKey returns n cryptographically random bytes, or an error. Returning the
// error is the whole point of the helper: the library call it replaced answered a
// CSPRNG failure with a nil slice, which the seeder then hex-encoded into a
// deployment's env file as an empty key, so a failed read produced a running
// installation with no session key rather than a refusal to start (#269).
func RandomKey(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return nil, errors.Wrap(err, "unable to read from the random number generator")
	}
	return buf, nil
}
