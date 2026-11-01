package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The not-found page is drawn in the signed-in user's page language over a ?ui_locales=es in its
// address, wherever it answers: under each group, on a path under no group, and for a directory of
// the static files (#631 decisions 4 and 7). On Automatic it follows the ?ui_locales=es.
func TestRoutes_TheNotFoundPageFollowsTheSignedInUsersPageLanguage(t *testing.T) {
	s, cookies := newSignedInConsole(t, "openid authserver:manage authserver:manage-account", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	cases := []struct {
		name         string
		pageLanguage string
		lang         string
		title        string
	}{
		{"chosen pt-BR", "pt-BR", "pt-BR", "Página não encontrada"},
		{"Automatic", "", "es", "Página no encontrada"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seed := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range cookies {
				seed.AddCookie(cookie)
			}
			session, err := s.sessionStore.Get(seed, builtin.AdminConsoleSessionName)
			require.NoError(t, err)
			session.Values[sessionkeys.PageLanguage] = tc.pageLanguage
			require.NoError(t, s.sessionStore.Save(seed, httptest.NewRecorder(), session))

			for _, target := range []string{"/admin/no/such/page", "/account/no/such/page", "/auth/no/such/page",
				"/no/such/page", "/static/"} {
				t.Run(target, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, target+"?ui_locales=es", nil)
					req.Header.Set("Accept-Language", "en")
					for _, cookie := range cookies {
						req.AddCookie(cookie)
					}
					rr := httptest.NewRecorder()
					s.router.ServeHTTP(rr, req)

					assert.Equal(t, http.StatusNotFound, rr.Code)
					assert.Contains(t, rr.Body.String(), `<html lang="`+tc.lang+`"`)
					assert.Contains(t, rr.Body.String(), tc.title)
				})
			}
		})
	}
}
