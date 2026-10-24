package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
)

// The form_post page is parsed alone, with no layout, so it marks its own language, and marks it as
// the layouts do: the tag of the catalog its sentences were rendered from, not the first preference
// asked for. de-DE has no catalog and reads English; nl-BE first and pt-BR third reads pt-BR (WCAG
// 2.2 SC 3.1.1, #645 decision 8).
func TestFormPost_ThePageIsMarkedWithTheCatalogLanguage(t *testing.T) {
	for acceptLanguage, want := range map[string]string{
		"de-DE":                      "en",
		"nl-BE,nl;q=0.9,pt-BR;q=0.8": "pt-BR",
	} {
		t.Run(acceptLanguage, func(t *testing.T) {
			r := withSessionSettings(httptest.NewRequest(http.MethodGet, "/auth/issue?ceremony="+testCeremonyId, nil))
			r.Header.Set("Accept-Language", acceptLanguage)
			r = r.WithContext(i18n.ResolveRequestLocale(r.Context(), r))
			w := httptest.NewRecorder()

			err := issueAuthCode(w, r, web.TemplateFS(),
				&record.Code{Code: "c0de", State: "st", RedirectURI: "https://example.com/callback"}, "form_post")

			require.NoError(t, err)
			assert.Contains(t, w.Body.String(), `<html lang="`+want+`">`)
		})
	}
}
