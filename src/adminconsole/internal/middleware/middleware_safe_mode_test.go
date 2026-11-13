package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/httpmw"
)

// safeModeSeen sends one request for target carrying cookies through the chain a console page goes
// through, CookieReset, SessionHandler and SafeMode, as routes.go mounts them, and reports whether
// the page below was drawn in safe mode.
func (h *sessionHarness) safeModeSeen(target string, cookies []*http.Cookie) (safe, reached bool) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	page := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		safe = reqctx.SafeModeFrom(r.Context())
	})
	chain := httpmw.CookieReset(h.store, sessionTestName)(
		h.middleware(h.parser).SessionHandler()(SafeMode(h.store, sessionTestName, h.errorPage)(page)))
	chain.ServeHTTP(httptest.NewRecorder(), req)
	return safe, reached
}

func (h *sessionHarness) verifiesTheStoredIDToken() {
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(verifiedStored, nil)
}

func signedInInSafeMode() map[string]any {
	values := signedIn(notDue())
	values[sessionkeys.SafeMode] = true
	return values
}

// goiabada_safe_mode=true on a console URL draws that page in safe mode and, for a signed-in
// browser, keeps its console session in safe mode from then on: the next page, with no parameter, is
// drawn safe too (#816 decision 2). Only true turns it on, as on the auth server.
func TestSafeMode_TheParameterKeepsASignedInSessionInSafeMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		target   string
		wantSafe bool
	}{
		{"true", "/admin/users?goiabada_safe_mode=true", true},
		{"false", "/admin/users?goiabada_safe_mode=false", false},
		{"1", "/admin/users?goiabada_safe_mode=1", false},
		{"TRUE", "/admin/users?goiabada_safe_mode=TRUE", false},
		{"empty", "/admin/users?goiabada_safe_mode=", false},
		{"absent", "/admin/users", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t)
			h.verifiesTheStoredIDToken()
			cookies := h.seed(signedIn(notDue()))

			safe, reached := h.safeModeSeen(tc.target, cookies)
			require.True(t, reached)
			assert.Equal(t, tc.wantSafe, safe, "the page the parameter is on")

			next, _ := h.safeModeSeen("/admin/clients", cookies)
			assert.Equal(t, tc.wantSafe, next, "the next page, with no parameter")
			if tc.wantSafe {
				assert.Equal(t, true, h.readBack(cookies).Values[sessionkeys.SafeMode])
			} else {
				assert.NotContains(t, h.readBack(cookies).Values, sessionkeys.SafeMode)
			}
		})
	}
}

// A signed-in session the sign-in put in safe mode draws every page safe, with no parameter.
func TestSafeMode_ASessionInSafeModeDrawsEveryPageSafe(t *testing.T) {
	h := newSessionHarness(t)
	h.verifiesTheStoredIDToken()
	cookies := h.seed(signedInInSafeMode())

	for _, target := range []string{"/admin/users", "/account/profile", "/", "/admin/users?goiabada_safe_mode=false"} {
		safe, reached := h.safeModeSeen(target, cookies)
		require.True(t, reached)
		assert.True(t, safe, target)
	}
}

// A browser that is not signed in has no console session to keep safe mode in: the parameter draws
// that page safe, which sends the sign-in it starts in safe mode, and writes nothing.
func TestSafeMode_ABrowserNotSignedInIsSafeForTheRequestAlone(t *testing.T) {
	h := newSessionHarness(t)

	safe, reached := h.safeModeSeen("/admin/users?goiabada_safe_mode=true", nil)
	require.True(t, reached)
	assert.True(t, safe)
	assert.Empty(t, h.backend.recordedWrites(), "no session is written")

	safe, _ = h.safeModeSeen("/admin/users", nil)
	assert.False(t, safe)
}

// Safe mode lasts until the console session is signed out. A session whose tokens are gone, signed
// out by SessionHandler here, is not in safe mode whatever it still holds.
func TestSafeMode_ASignedOutSessionIsNotInSafeMode(t *testing.T) {
	h := newSessionHarness(t)
	h.parser.On("DecodeAndValidateStoredIDToken", mock.Anything, storedIDTokenRaw).Return(nil, assert.AnError)
	cookies := h.seed(signedInInSafeMode())

	safe, reached := h.safeModeSeen("/admin/users", cookies)
	require.True(t, reached)
	assert.False(t, safe)
}
