package render

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRender_LayoutsAreMarkedWithTheCatalogLanguage holds both page layouts, through the real
// templates, to marking a page with the language it is written in: the tag of the catalog it was
// rendered from, not the first preference asked for. A browser asking for de-DE, with no German
// catalog, reads an English page; one asking for nl-BE first and pt-BR third reads pt-BR. A screen
// reader chooses its voice from the attribute (WCAG 2.2 SC 3.1.1, #645 decisions 7 and 8).
func TestRender_LayoutsAreMarkedWithTheCatalogLanguage(t *testing.T) {
	for _, tc := range []struct{ layout, page string }{
		{"/layouts/auth_layout.html", "/logged_out.html"},
		{"/layouts/no_menu_layout.html", "/not_found.html"},
	} {
		for acceptLanguage, want := range map[string]string{
			"de-DE":                      "en",
			"nl-BE,nl;q=0.9,pt-BR;q=0.8": "pt-BR",
			"en-GB":                      "en",
		} {
			t.Run(tc.layout+" "+acceptLanguage, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Accept-Language", acceptLanguage)
				req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{AppName: "Test", UITheme: "dark"}))
				req = req.WithContext(i18n.ResolveRequestLocale(req.Context(), req))

				buf, err := New(web.TemplateFS(), web.StaticFS()).RenderTemplateToBuffer(req, tc.layout, tc.page,
					map[string]interface{}{})

				require.NoError(t, err)
				assert.Contains(t, buf.String(), `<html lang="`+want+`" data-theme="dark">`)
			})
		}
	}
}
