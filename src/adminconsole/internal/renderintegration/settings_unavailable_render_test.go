package renderintegration

import (
	"html"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/requestid"
	"github.com/leodip/goiabada/core/routing"
	"github.com/stretchr/testify/assert"
)

// The page a request without settings is answered with, through the real template: a 500 in the
// request's language, its title and message, the request id the log records the cause under, and
// the stylesheet, with no layout and no application name, since both read the settings it lacks.
func TestRender_SettingsUnavailable(t *testing.T) {
	var requestID string
	router := routing.New()
	router.Use(requestid.Middleware)
	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		requestID = requestid.FromContext(r.Context())
		r = r.WithContext(i18n.WithLocale(r.Context(), true, "pt-BR"))
		render.New(web.TemplateFS(), web.StaticFS()).SettingsUnavailable(w, r,
			"adminconsole.error.settings_unavailable_title", "adminconsole.error.settings_unavailable")
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "text/html; charset=UTF-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	out := w.Body.String()
	assert.Contains(t, out, `<html lang="pt-BR">`)
	assert.Contains(t, out, `<title>Não foi possível acessar o servidor de autenticação</title>`)
	assert.Contains(t, out, `<h1 class="auth-title">Não foi possível acessar o servidor de autenticação</h1>`)
	assert.Contains(t, out, "<p>"+html.EscapeString(i18n.T(i18n.WithLocale(t.Context(), true, "pt-BR"), "adminconsole.error.settings_unavailable"))+"</p>")
	assert.Contains(t, out, `<code class="break-all font-mono text-ink">`+requestID+`</code>`)
	assert.Regexp(t, `<link rel="stylesheet" href="/static/main.css\?v=[0-9a-f]+">`, out)
}

// The page is marked with the language it is written in, the catalog's, not the first preference
// asked for: sv-SE has no catalog and reads English, and nl-BE first with pt-BR third reads pt-BR
// (#645 decision 8).
func TestRender_SettingsUnavailableIsMarkedWithTheCatalogLanguage(t *testing.T) {
	for acceptLanguage, want := range map[string]string{
		"sv-SE":                      "en",
		"nl-BE,nl;q=0.9,pt-BR;q=0.8": "pt-BR",
	} {
		t.Run(acceptLanguage, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Language", acceptLanguage)
			w := httptest.NewRecorder()
			i18n.Locale(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				render.New(web.TemplateFS(), web.StaticFS()).SettingsUnavailable(w, r,
					"adminconsole.error.settings_unavailable_title", "adminconsole.error.settings_unavailable")
			})).ServeHTTP(w, req)

			assert.Equal(t, http.StatusInternalServerError, w.Code)
			assert.Contains(t, w.Body.String(), `<html lang="`+want+`">`)
		})
	}
}
