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

// The console reads in Indonesian for a ui_locales asking for id and for a browser asking for id-ID
// or in (#668).
func TestIndonesian_AdminPageUsesQueryOrRegionalHeader(t *testing.T) {
	for _, tc := range []struct{ target, accept string }{
		{"/admin/clients?ui_locales=id", "en"},
		{"/admin/clients", "id-ID"},
		{"/admin/clients", "in"},
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
			assert.Contains(t, w.Body.String(), `<html lang="id"`)
			assert.Contains(t, w.Body.String(), `data-catalog-lang="id"`)
			assert.Contains(t, w.Body.String(), "Client baru")
			assert.Contains(t, w.Body.String(), "Belum ada client.")
		})
	}
}

func TestIndonesian_ConsoleRefusalIsRenderedOnItsForm(t *testing.T) {
	req := handlertest.Request(http.MethodPost, "/admin/resources/7/delete",
		handlertest.WithAccessToken(), handlertest.WithPathValue("resourceId", "7"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test"}),
		handlertest.WithLocale("id-ID"),
		handlertest.WithForm(url.Values{"resourceIdentifier": {"shipping"}}))
	w := httptest.NewRecorder()
	adminresourcehandlers.HandleDeletePost(render.New(web.TemplateFS(), web.StaticFS()), resourceToDelete{}, "https://console.example.test").ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `lang="id"`)
	assert.Contains(t, html.UnescapeString(w.Body.String()), "Itu bukan pengenal sumber daya ini. Ketik persis seperti yang tertera di atas.")
	assert.Contains(t, w.Body.String(), `aria-invalid="true"`)
}
