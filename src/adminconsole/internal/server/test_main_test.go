package server

import (
	"os"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The middleware chain this package drives answers a refused request through
// i18n.T. Without a loaded bundle T echoes the key, and every body assertion here
// would pass against the key rather than against the message, which is exactly the
// state TestInitMiddleware_RefusalsAreLocalized exists to detect.
func TestMain(m *testing.M) {
	if _, err := i18n.LoadBundle(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
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
