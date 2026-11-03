package main

import (
	"context"
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
// administrators would gain a handle left on disk, or the deployment's Keep users signed in setting
// would decide nothing, with every store test still passing (#431, #743).
func TestNewSessionStore_ASignedInCookieFollowsTheRowsExpiryWhileTheRuleKeepsItSignedIn(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, keep := range []bool{true, false} {
			name := map[bool]string{false: "http", true: "https"}[secure] + "/" +
				map[bool]string{true: "kept signed in", false: "not kept"}[keep]
			t.Run(name, func(t *testing.T) {
				var asked map[string]any
				keepSignedIn := func(_ context.Context, values map[string]any) (bool, error) {
					asked = values
					return keep, nil
				}
				store, err := newSessionStore(sessiontest.NewMemoryBackend(), keepSignedIn, secure, sessionstore.KeyPair{
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

				assert.Equal(t, "a-user-session", asked[sessionkeys.SessionIdentifier],
					"the rule is asked about the session being written")
				setCookie := w.Result().Header.Values("Set-Cookie")
				require.Len(t, setCookie, 1)
				cookie := w.Result().Cookies()[0]
				if keep {
					assert.Contains(t, setCookie[0], "Max-Age=",
						"the cookie carries an expiry, so single sign-on survives a browser restart: %s", setCookie[0])
					// sessiontest's rows expire an hour from each write, and the cookie follows the row.
					assert.InDelta(t, 3600, cookie.MaxAge, 5)
				} else {
					assert.NotContains(t, setCookie[0], "Max-Age", "the cookie ends with the browser")
					assert.NotContains(t, setCookie[0], "Expires")
				}
				assert.Equal(t, secure, cookie.Secure)
				assert.Equal(t, secure, strings.HasPrefix(cookie.Name, "__Host-"))
			})
		}
	}
}
