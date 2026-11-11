package server

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A sign-in that has ended under a page whose scripts still send requests, through the real route
// table and middleware chain: the session keeps its cookie and row but holds no tokens, as a refused
// refresh leaves it. Each route a page script sends to answers the script's request with the
// session-ended JSON, which the script follows to the session-ended route, and seals no sign-in;
// the same request as a navigation is still sent to sign in. A route mounted outside the chain, or a
// marker the middleware no longer reads, fails here.
func TestInitRoutes_AScriptsRequestAfterTheSignInEndedIsToldSo(t *testing.T) {
	s, cookies := newSignedInConsole(t, "openid authserver:manage authserver:manage-account", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("a request with no tokens reached the admin API: %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})
	sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin"}
	ended := serveWithCookies(s, http.MethodGet, "/auth/session-ended", cookies, sameOrigin)
	require.Equal(t, http.StatusFound, ended.Code)
	require.False(t, storedTokens(t, s, cookies), "the session holds no tokens")

	script := map[string]string{"Sec-Fetch-Site": "same-origin", "X-Requested-With": "XMLHttpRequest"}
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/admin/settings/branding/assets/logo"},
		{http.MethodPost, "/admin/settings/branding/assets/favicon"},
		{http.MethodPost, "/admin/settings/branding/assets/background"},
		{http.MethodPost, "/admin/settings/branding/assets/font"},
		{http.MethodPost, "/admin/clients/7/logo"},
		{http.MethodDelete, "/admin/clients/7/logo"},
		{http.MethodPost, "/admin/users/7/picture"},
		{http.MethodDelete, "/admin/users/7/picture"},
		{http.MethodPost, "/account/picture"},
		{http.MethodDelete, "/account/picture"},
		{http.MethodPost, "/admin/users/7/sessions"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			rec := serveWithCookies(s, route.method, route.path, cookies, script)

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			assert.JSONEq(t, `{"error":"session_ended","error_description":"Your sign-in has ended. Sign in again."}`, rec.Body.String())
			assert.Empty(t, rec.Result().Cookies(), "no sign-in is sealed")
		})
	}

	navigation := serveWithCookies(s, http.MethodGet, "/admin/settings/branding", cookies, sameOrigin)
	assert.Equal(t, http.StatusFound, navigation.Code)
	assert.Contains(t, navigation.Header().Get("Location"), "/auth/authorize?", "a navigation is sent to sign in")
}
