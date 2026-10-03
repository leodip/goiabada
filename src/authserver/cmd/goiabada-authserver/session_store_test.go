package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
)

// The auth server's half of #266's split, pinned where this binary chooses it: the store's own
// tests pin what each lifetime writes, and nothing but this pins which one main passes. Crossed,
// end users would lose single sign-on at every browser restart and administrators would gain a
// handle left on disk, with every store test still passing (#431).
func TestNewSessionStore_TheEndUsersCookieFollowsTheRowsExpiry(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			store, err := newSessionStore(sessiontest.NewMemoryBackend(), secure, sessionstore.KeyPair{
				AuthenticationKey: []byte("12345678901234567890123456789012"),
				EncryptionKey:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
			}, nil)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()
			session, err := store.Get(req, sessionkeys.AuthServerSessionName)
			require.NoError(t, err)
			session.Values[sessionkeys.SessionIdentifier] = "a-user-session"
			require.NoError(t, store.Save(req, w, session))

			setCookie := w.Result().Header.Values("Set-Cookie")
			require.Len(t, setCookie, 1)
			assert.True(t, strings.Contains(setCookie[0], "Max-Age="),
				"the cookie carries an expiry, so single sign-on survives a browser restart: %s", setCookie[0])

			cookie := w.Result().Cookies()[0]
			// sessiontest's rows expire an hour from each write, and the cookie follows the row.
			assert.InDelta(t, 3600, cookie.MaxAge, 5)
			assert.Equal(t, secure, cookie.Secure)
			assert.Equal(t, secure, strings.HasPrefix(cookie.Name, "__Host-"))
		})
	}
}
