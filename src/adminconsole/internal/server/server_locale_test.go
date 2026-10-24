package server

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/publicsettings"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/routing"
)

// TestInitMiddleware_RefusalsAreLocalized makes the claim no unit test of any one
// middleware can: that the chain Server.initMiddleware mounts puts a localizer on
// the context before the middlewares that answer a request without reaching a
// handler.
//
// The middleware tables in internal/middleware pass with the chain in either order,
// because they mount the locale middleware themselves. This drives the real
// initMiddleware, so moving i18n.Locale back below middleware.SettingsCache
// fails the settings rows here and nothing else in the repository.
//
// The settings cache points at an address nothing listens on, which is what keeps
// this a unit test: the fetch fails deterministically with no auth server to run,
// and the refusal it writes is one of the two responses under test.
func TestInitMiddleware_RefusalsAreLocalized(t *testing.T) {
	const unreachableAuthServer = "http://127.0.0.1:1"

	// Registered on the router initMiddleware returns, not on s.router: that is the
	// application branch, and the settings cache is only on that branch.
	newServer := func() *Server {
		s := &Server{
			router:        routing.New(),
			sessionStore:  newTestSessionStore(),
			settingsCache: publicsettings.NewCache(publicsettings.NewClient(unreachableAuthServer, nil, nil), publicsettings.DefaultTTL, metrics.NewRegistry()),
			cfg:           &config.Config{},
			metrics:       metrics.NewRegistry(),
			templateFS:    web.TemplateFS(),
			staticFS:      web.StaticFS(),
		}
		app := s.initMiddleware()
		app.Get("/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		app.Post("/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return s
	}

	// English and Portuguese must differ for any of this to mean anything: a chain
	// that never resolved a locale would still match a key whose two entries agree.
	english := func(key string) string { return i18n.T(context.Background(), key) }
	translated := func(t *testing.T, key, locale string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/?ui_locales="+locale, nil)
		out := i18n.T(i18n.ResolveRequestLocale(req.Context(), req), key)
		if out == english(key) {
			t.Fatalf("the two catalogs answer %q identically, so no assertion below can tell a "+
				"localized refusal from an unlocalized one", key)
		}
		return out
	}

	type refusalCase struct {
		name string
		// request builds the request under test; the response it draws is one of the
		// two refusals, never the handler.
		request func() *http.Request
		key     string
		status  int
		locale  string
	}
	tests := []refusalCase{
		{
			name: "the settings refusal answers in the language the browser asked for",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
				req.Header.Set("Accept-Language", "pt-BR")
				return req
			},
			key:    "adminconsole.error.settings_unavailable",
			status: http.StatusInternalServerError,
			locale: "pt-BR",
		},
		{
			name: "the settings refusal honours ui_locales",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/admin/clients?ui_locales=pt-BR", nil)
			},
			key:    "adminconsole.error.settings_unavailable",
			status: http.StatusInternalServerError,
			locale: "pt-BR",
		},
		{
			name: "the settings refusal falls back to English when the request says nothing",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
			},
			key:    "adminconsole.error.settings_unavailable",
			status: http.StatusInternalServerError,
		},
		{
			// The CSRF pair is mounted on the root router, above the branch that
			// carries the locale middleware, so this row does not depend on the
			// order the rows above pin: it passes only because httpmw.CSRF
			// resolves a tentative localizer of its own.
			name: "the CSRF refusal answers in the language the browser asked for",
			request: func() *http.Request {
				form := url.Values{"name": {"whatever"}}
				req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", "https://relying-party.example")
				req.Header.Set("Sec-Fetch-Site", "cross-site")
				req.Header.Set("Accept-Language", "pt-BR")
				return req
			},
			key:    "error.csrf_refused",
			status: http.StatusForbidden,
			locale: "pt-BR",
		},
		{
			name: "the CSRF refusal falls back to English when the request says nothing",
			request: func() *http.Request {
				form := url.Values{"name": {"whatever"}}
				req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.Header.Set("Origin", "https://relying-party.example")
				req.Header.Set("Sec-Fetch-Site", "cross-site")
				return req
			},
			key:    "error.csrf_refused",
			status: http.StatusForbidden,
		},
	}

	for _, locale := range []string{"es", "es-MX"} {
		tests = append(tests, refusalCase{
			name: "settings refusal in " + locale,
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
				req.Header.Set("Accept-Language", locale)
				return req
			},
			key:    "adminconsole.error.settings_unavailable",
			status: http.StatusInternalServerError,
			locale: locale,
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := english(tt.key)
			if tt.locale != "" {
				want = translated(t, tt.key, tt.locale)
			}

			rr := httptest.NewRecorder()
			newServer().router.ServeHTTP(rr, tt.request())

			if rr.Code != tt.status {
				t.Fatalf("got status %d, want %d (body %q)", rr.Code, tt.status, rr.Body.String())
			}
			// The settings refusal is a page, the CSRF one plain text; each holds the sentence.
			if body := rr.Body.String(); !strings.Contains(body, html.EscapeString(want)) {
				t.Errorf("body = %q, want it to hold %q", body, want)
			}
		})
	}
}
