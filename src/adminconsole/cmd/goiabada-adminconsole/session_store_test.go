package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// The admin console's half of #266's split, pinned where this binary chooses it: the store's own
// tests pin what each lifetime writes, and nothing but this pins which one main passes. Crossed,
// the handle to the deployment's most privileged session would be written to disk with every
// store test still passing (#431).
//
// Asserted on the raw header: net/http parses an absent Max-Age and a Max-Age of zero to
// different values, and only the header says that nothing was written at all.
func TestNewSessionStore_TheAdministratorsCookieEndsWithTheBrowser(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			store, err := newSessionStore(sessiontest.NewMemoryBackend(), secure, sessionstore.KeyPair{
				AuthenticationKey: []byte("12345678901234567890123456789012"),
				EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
			}, nil)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			session, err := store.Get(req, coreconstants.AdminConsoleSessionName)
			require.NoError(t, err)
			session.Values[sessionkeys.SessionKeyJwt] = "a-token-set"
			require.NoError(t, store.Save(req, w, session))

			setCookie := w.Result().Header.Values("Set-Cookie")
			require.Len(t, setCookie, 1)
			assert.NotContains(t, setCookie[0], "Max-Age", "the browser drops the cookie when it closes")
			assert.NotContains(t, setCookie[0], "Expires", "the browser drops the cookie when it closes")

			cookie := w.Result().Cookies()[0]
			assert.Equal(t, secure, cookie.Secure)
			assert.Equal(t, secure, strings.HasPrefix(cookie.Name, "__Host-"))
		})
	}
}
