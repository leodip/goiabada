package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/core/sessionstore/sessiontest"
	"github.com/stretchr/testify/assert"
)

// The console's router sends the security headers on every answer, a page's and a static
// file's (#518 decision 6).
//
// httpmw.SecurityHeaders has its own tests, which pass whatever router it is mounted on, and
// the auth server's middleware-chain test names it. Nothing in this module did, so dropping
// the console's mount, or moving it below the branch that serves /static/, left this module's
// unit tier green while the console's pages lost their Content-Security-Policy and their
// clickjacking protection. The test reads what the browser receives rather than the chain's
// shape, so it survives a reordering that keeps the headers.
//
// The values are written out here rather than read from the middleware, so the test is an
// independent statement of what the console sends.

const consolePolicy = "script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"

func TestInitMiddleware_EveryAnswerCarriesTheSecurityHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		baseURL string
		hsts    string
	}{
		{name: "over http, without Strict-Transport-Security", baseURL: "http://console.example", hsts: ""},
		{name: "over https, with Strict-Transport-Security", baseURL: "https://console.example", hsts: "max-age=31536000; includeSubDomains"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := newCountingSettingsServer(t)
			s := newStaticBranchTestServer(settings.URL, newTestSessionStoreOver(sessiontest.NewMemoryBackend()))
			s.cfg.AdminConsole.BaseURL = tc.baseURL
			app := s.initMiddleware()
			s.serveStaticFiles()
			app.Get("/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
			})

			for _, path := range []string{"/admin/clients", "/static/probe.css"} {
				t.Run(path, func(t *testing.T) {
					recorder := httptest.NewRecorder()
					s.router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

					assert.Equal(t, http.StatusOK, recorder.Code, "the answer must be the page or the file itself")
					headers := recorder.Header()
					assert.Equal(t, []string{consolePolicy}, headers.Values("Content-Security-Policy"))
					assert.Equal(t, "DENY", headers.Get("X-Frame-Options"))
					assert.Equal(t, "nosniff", headers.Get("X-Content-Type-Options"))
					assert.Equal(t, "same-origin", headers.Get("Referrer-Policy"))
					assert.Equal(t, tc.hsts, headers.Get("Strict-Transport-Security"))
				})
			}
		})
	}
}
