package renderintegration

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGerman_AdminPageUsesQueryOrAustrianHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/admin/clients?ui_locales=de", "en"},
		{"/admin/clients", "de-AT"},
	} {
		t.Run(tc.target+tc.accept, func(t *testing.T) {
			req := handlertest.Request(http.MethodGet, tc.target,
				handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}))
			req.Header.Set("Accept-Language", tc.accept)
			req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))
			w := httptest.NewRecorder()
			err := render.New(web.TemplateFS(), web.StaticFS()).RenderTemplate(w, req,
				"layouts/menu_layout.html", "admin_clients.html", map[string]interface{}{})
			require.NoError(t, err)
			assert.Contains(t, w.Body.String(), `<html lang="de"`)
			assert.Contains(t, w.Body.String(), `data-catalog-lang="de"`)
			assert.Contains(t, w.Body.String(), "Neuer Client")
			assert.Contains(t, w.Body.String(), "Noch keine Clients vorhanden.")
		})
	}
}

func TestGerman_ConsoleRefusalIsRenderedOnItsForm(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithPathValue("resourceId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"}),
		handlertest.WithLocale("de-AT"),
		handlertest.WithForm(url.Values{"resourceIdentifier": {"shipping"}}))
	w := httptest.NewRecorder()
	adminresourcehandlers.HandleDeletePost(render.New(web.TemplateFS(), web.StaticFS()), resourceToDelete{}, "https://console.example.test").ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `lang="de"`)
	assert.Contains(t, html.UnescapeString(w.Body.String()), "Das ist nicht die Kennung dieser Ressource. Geben Sie sie wie oben angezeigt ein.")
	assert.Contains(t, w.Body.String(), `aria-invalid="true"`)
}
