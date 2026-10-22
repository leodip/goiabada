package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
)

// #411 through the real route table and the real middleware chain, with a signed-in session. The
// handler tests call HandleLogoutConfirmGet and HandleLogoutPost directly, past httpmw.CSRF and
// initRoutes, so they pass whichever handler GET /auth/logout is wired to, with no POST route at
// all, and with /auth/logout exempted from the origin check. Each of those fails here.

// logoutRequestPath is the admin API endpoint the sign-out asks for the form binding.
const logoutRequestPath = "/api/v1/account/logout-request"

// logoutConsole is a signed-in console whose auth server records every admin API path it is asked
// for and answers the logout request with the form binding.
func logoutConsole(t *testing.T) (*Server, []*http.Cookie, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var asked []string
	s, cookies := newSignedInConsole(t, "openid authserver:manage-account", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == logoutRequestPath {
			_, _ = w.Write([]byte(`{"method":"POST","endpoint":"https://op.example.com/auth/logout",` +
				`"params":{"id_token_hint":"the.id.token","post_logout_redirect_uri":"https://console.example.test","state":"s"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	return s, cookies, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), asked...)
	}
}

func serveWithCookies(s *Server, method, path string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if method == http.MethodPost {
		req = httptest.NewRequest(method, path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	return rec
}

// storedTokens reports whether the session the cookies name still holds the console's tokens, read
// through the production store as the browser's next request would.
func storedTokens(t *testing.T, s *Server, cookies []*http.Cookie) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	sess, err := s.sessionStore.Get(req, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	_, ok := sess.Values[sessionkeys.JWT]
	return ok
}

func TestInitRoutes_ACrossSiteGetOfTheSignOutOnlyAsksToConfirm(t *testing.T) {
	s, cookies, asked := logoutConsole(t)

	rec := serveWithCookies(s, http.MethodGet, "/auth/logout", cookies, map[string]string{
		"Sec-Fetch-Site": "cross-site",
	})

	assert.Equal(t, http.StatusOK, rec.Code, "the confirmation page, not a sign-out")
	assert.Contains(t, rec.Body.String(), `<form method="post" action="/auth/logout"`)
	assert.NotContains(t, asked(), logoutRequestPath, "the GET asks the auth server for nothing")
	assert.True(t, storedTokens(t, s, cookies), "the navigation signed nobody out")
}

func TestInitRoutes_TheOriginCheckRefusesASignOutPostedFromAnotherSite(t *testing.T) {
	for _, headers := range []map[string]string{
		{"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
		{"Origin": "https://sibling.example.test", "Sec-Fetch-Site": "same-site"},
	} {
		t.Run(headers["Sec-Fetch-Site"], func(t *testing.T) {
			s, cookies, asked := logoutConsole(t)

			rec := serveWithCookies(s, http.MethodPost, "/auth/logout", cookies, headers)

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, i18n.T(context.Background(), "error.csrf_refused"), strings.TrimSpace(rec.Body.String()),
				"the origin check's refusal, not a handler's")
			assert.NotContains(t, asked(), logoutRequestPath, "the sign-out never ran")
			assert.True(t, storedTokens(t, s, cookies), "the tokens survive the refused POST")
		})
	}
}

func TestInitRoutes_ASameOriginSignOutPostEndsBothSessions(t *testing.T) {
	s, cookies, asked := logoutConsole(t)

	rec := serveWithCookies(s, http.MethodPost, "/auth/logout", cookies, map[string]string{
		"Sec-Fetch-Site": "same-origin",
	})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `action="https://op.example.com/auth/logout"`,
		"the form binding that ends the auth server's session too")
	assert.Contains(t, asked(), logoutRequestPath, "the auth server was asked for the form binding")
	assert.False(t, storedTokens(t, s, cookies), "the console's tokens are gone")
}

// The session-ended route's cross-site arm, end to end (#411 review, F4). An administrator whose
// auth server session ended follows another site's link to a console page; the admin API answers
// 401 and the page helper redirects to /auth/session-ended, and the browser reports that hop with
// the navigation's initiator, cross-site. It is sent home with the session as it was, not
// dead-ended on the origin check's 403, and the next same-origin arrival signs it out.
func TestInitRoutes_AnEndedSessionMetFromAnotherSiteIsSentHomeNotRefused(t *testing.T) {
	s, cookies := newSignedInConsole(t, "openid authserver:manage", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
	})
	crossSite := map[string]string{"Sec-Fetch-Site": "cross-site"}

	page := serveWithCookies(s, http.MethodGet, "/admin/clients", cookies, crossSite)
	require.Equal(t, http.StatusFound, page.Code)
	require.Equal(t, "/auth/session-ended", page.Header().Get("Location"))

	hop := serveWithCookies(s, http.MethodGet, "/auth/session-ended", cookies, crossSite)
	assert.Equal(t, http.StatusFound, hop.Code, "sent on, not refused")
	assert.Equal(t, "/", hop.Header().Get("Location"))
	assert.NotContains(t, hop.Body.String(), i18n.T(context.Background(), "error.csrf_refused"))
	assert.True(t, storedTokens(t, s, cookies), "a cross-site navigation clears nothing")

	home := serveWithCookies(s, http.MethodGet, "/", cookies, crossSite)
	assert.Equal(t, http.StatusOK, home.Code, "the home page calls no admin API, so nothing loops")

	again := serveWithCookies(s, http.MethodGet, "/auth/session-ended", cookies, map[string]string{
		"Sec-Fetch-Site": "same-origin",
	})
	assert.Equal(t, http.StatusFound, again.Code)
	assert.False(t, storedTokens(t, s, cookies), "the console's own navigation signs the session out")
}
