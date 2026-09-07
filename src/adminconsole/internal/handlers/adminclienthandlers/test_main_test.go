package adminclienthandlers

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"
)

func TestMain(m *testing.M) {
	config.Init()
	code := m.Run()
	os.Exit(code)
}

// newTestSessionStore is the real store over an in-memory backend, which is what these
// tests drive now that the browser session is a row rather than a cookie (#266). It
// replaces a cookie store built from a random key: nothing here asserts on the cookie's
// contents, so what the double owed was a working Get and Save, and the real store over
// NewMemoryBackend gives both without a second implementation of either.
//
// The keys are literals rather than freshly generated ones, matching the pattern the
// store's other test callers already use. They never vary and nothing reads them, so
// generating them would only add an error to check in a helper that cannot fail.
func newTestSessionStore() *sessionstore.ServerSideStore {
	return sessionstore.NewServerSideStore(
		sessionstore.NewMemoryBackend(),
		constants.SessionKeyJwt,
		false,
		[]byte("12345678901234567890123456789012"),
		[]byte("abcdefghijklmnopqrstuvwxyz123456"),
	)
}
