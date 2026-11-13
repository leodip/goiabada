package handlers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
)

// A sign-in the console started in safe mode keeps the console session in safe mode until it is
// signed out: the handshake says so, and the callback writes it into the signed-in session. A
// sign-in started out of safe mode leaves the session out of it, even over a session that held it
// from an earlier sign-in, so safe mode never outlives the sign-in it was asked for (#816
// decision 2).
func TestHandleAuthCallbackPost_KeepsTheSignInsSafeModeForTheSession(t *testing.T) {
	for _, tc := range []struct {
		name      string
		handshake string
		planted   map[string]any
		wantSafe  bool
	}{
		{"asked for", "true", nil, true},
		{"not asked for", "", nil, false},
		{"not asked for, over a session that held it", "", map[string]any{sessionkeys.SafeMode: true}, false},
		{"asked for, over a session that did not", "true", map[string]any{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCallbackHarness(t)
			handlertest.RefuseInternalServerError(t, h.httpHelper)
			values := handshake()
			if tc.handshake != "" {
				values[sessionkeys.SafeMode] = tc.handshake
			}
			cookies := []*http.Cookie{h.handshakeCookie(values)}
			if tc.planted != nil {
				cookies = append(cookies, h.seedSession(tc.planted))
			}

			w := h.serve(&recordingExchanger{response: h.tokenResponse()}, cookies, callbackForm())

			require.Equal(t, http.StatusFound, w.Code)
			sess := h.readBack(h.assertHandshakeRemoved(w, true, true))
			require.False(t, sess.IsNew)
			if tc.wantSafe {
				assert.Equal(t, true, sess.Values[sessionkeys.SafeMode])
			} else {
				assert.NotContains(t, sess.Values, sessionkeys.SafeMode)
			}
		})
	}
}
