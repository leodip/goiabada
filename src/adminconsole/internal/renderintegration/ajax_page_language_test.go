package renderintegration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminresourcehandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
)

// A request a page sends without a reload is a request of its own, and the console resolves its
// language again from what that request carries. A page opened with ?ui_locales=pt-BR in a browser
// in English would then show its dialog's refusals in English, the API's and the console's own
// alike. So each layout publishes the catalog its page rendered from, and every request a page
// script sends names it back as ui_locales, which the locale middleware reads as explicit intent the
// browser's Accept-Language does not override (#559 decisions 3 and 7). A user's page language wins
// over both, and drew the page too, so a script naming back a language the page no longer has, a tab
// left open across a change of choice, still gets the user's choice (#631 decision 4).

// TestRender_LayoutsPublishTheCatalogLanguage holds both layouts to naming the catalog the page
// rendered from, not the first preference asked for: a browser asking for nl-BE first and pt-BR
// third renders pt-BR, and a script naming nl-BE back would get English. <html lang> names the same
// catalog, since that is the language the page is written in: a browser asking for sv-SE, with no
// Swedish catalog, reads an English page, and a screen reader choosing its voice from a lang of sv-SE
// would read it in Swedish (WCAG 2.2 SC 3.1.1, #645 decisions 7 and 8).
func TestRender_LayoutsPublishTheCatalogLanguage(t *testing.T) {
	for _, tc := range []struct {
		layout, page string
		bind         map[string]interface{}
	}{
		{"/layouts/menu_layout.html", "/admin_resources_permissions.html", map[string]interface{}{
			"resourceId": 7, "resourceIdentifier": "billing", "resourceDescription": "Billing",
			"isSystemLevelResource": false, "builtInPermissionIdentifiers": []string{},
			"savedSuccessfully": false, "permissions": []api.PermissionResponse{},
		}},
		{"/layouts/no_menu_layout.html", "/index.html", map[string]interface{}{
			"AuthServerBaseUrl": "https://auth.example", "IsAuthenticated": false,
			"LoggedInUser": "", "LogoutLink": "", "SessionEnded": false,
		}},
	} {
		for acceptLanguage, want := range map[string]string{
			"nl-BE,nl;q=0.9,pt-BR;q=0.8": "pt-BR",
			"en-US":                      "en",
			"sv-SE":                      "en",
		} {
			t.Run(tc.layout+" "+acceptLanguage, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Accept-Language", acceptLanguage)
				req = req.WithContext(reqctx.WithSettings(req.Context(),
					&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"}))
				w := httptest.NewRecorder()
				var renderErr error
				i18n.Locale(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					renderErr = render.New(web.TemplateFS(), web.StaticFS()).RenderTemplate(w, r, tc.layout, tc.page, tc.bind)
				})).ServeHTTP(w, req)

				require.NoError(t, renderErr)
				assert.Contains(t, w.Body.String(), `<html lang="`+want+`" data-catalog-lang="`+want+`"`)
			})
		}
	}
}

// TestAjax_ThePagesLanguageOutranksTheBrowser drives a dialog's save through the console's real
// locale chain, its API client and the permissions handler, in a browser in English, with an ID
// token whose locale claim is English too, which no console page follows any more. Named back as
// ui_locales, the page's pt-BR reaches the API as its Accept-Language and the dialog's sentence is
// Portuguese, the API's refusal and the console's own alike; without it, the browser's English
// wins, which is what the page scripts must not leave to chance. A user's page language of pt-BR
// wins over a page naming Spanish back.
func TestAjax_ThePagesLanguageOutranksTheBrowser(t *testing.T) {
	for _, tc := range []struct {
		name, target, wantAPILanguage string
		pageLanguage                  string
		gone                          bool
		status                        int
		code, want                    string
	}{
		{"an API refusal, the page's language named", "/admin/resources/7/permissions?ui_locales=pt-BR", "pt-BR", "",
			false, http.StatusConflict, "CONCURRENT_UPDATE",
			"A lista foi alterada por outro salvamento depois de ser carregada. Nada foi salvo: recarregue a lista e faça a alteração novamente."},
		{"a console refusal, the page's language named", "/admin/resources/7/permissions?ui_locales=pt-BR", "pt-BR", "",
			true, http.StatusNotFound, "not_found",
			"Desculpe, não foi possível encontrar o item solicitado. Ele pode ter sido excluído, ou o endereço pode estar incorreto."},
		{"an API refusal, no language named", "/admin/resources/7/permissions", "en", "",
			false, http.StatusConflict, "CONCURRENT_UPDATE",
			"The list was changed by another save after it was loaded. Nothing was saved: reload it and make the change again."},
		{"an API refusal, the user's page language over the one named", "/admin/resources/7/permissions?ui_locales=es", "pt-BR", "pt-BR",
			false, http.StatusConflict, "CONCURRENT_UPDATE",
			"A lista foi alterada por outro salvamento depois de ser carregada. Nada foi salvo: recarregue a lista e faça a alteração novamente."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var apiLanguage string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					if tc.gone {
						w.WriteHeader(http.StatusNotFound)
						_, _ = w.Write([]byte(`{"error_code":"NOT_FOUND","error_description":"Resource not found"}`))
						return
					}
					_, _ = w.Write([]byte(`{"resource":{"id":7,"resourceIdentifier":"billing"}}`))
					return
				}
				apiLanguage = r.Header.Get("Accept-Language")
				ctx := i18n.ResolveRequestLocale(r.Context(), r)
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(api.ErrorResponse{ErrorCode: "CONCURRENT_UPDATE",
					ErrorDescription: i18n.T(ctx, i18n.ErrCodeListSaveChangedSinceLoaded)})
			}))
			defer upstream.Close()

			req := handlertest.Request(http.MethodPost, tc.target,
				handlertest.WithJwtInfo(oauthclient.JwtInfo{
					TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken},
					IdToken:       &oauth.JwtToken{Claims: jwt.MapClaims{"locale": "en"}},
				}),
				handlertest.WithPathValue("resourceId", "7"),
				handlertest.WithBody(strings.NewReader(`{"resourceId":7,"permissions":[],"expectedPermissions":[]}`)))
			req.Header.Set("Accept-Language", "en")
			store := newPageLanguageStore(t)
			if tc.pageLanguage != "" {
				seed := httptest.NewRequest(http.MethodGet, "/", nil)
				sess, err := store.Get(seed, builtin.AdminConsoleSessionName)
				require.NoError(t, err)
				sess.Values[sessionkeys.PageLanguage] = tc.pageLanguage
				seeded := httptest.NewRecorder()
				require.NoError(t, store.Save(seed, seeded, sess))
				for _, c := range seeded.Result().Cookies() {
					req.AddCookie(c)
				}
			}
			w := httptest.NewRecorder()
			handler := adminresourcehandlers.HandlePermissionsPost(render.New(nil, nil), nil,
				apiclient.NewAuthServerClient(upstream.URL, nil, nil))
			i18n.Locale(nil)(middleware.PageLanguage(store, builtin.AdminConsoleSessionName)(handler)).ServeHTTP(w, req)

			require.Equal(t, tc.status, w.Code)
			var response map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, tc.code, response["error"])
			assert.Equal(t, tc.want, response["error_description"])
			if !tc.gone {
				assert.Equal(t, tc.wantAPILanguage, apiLanguage)
			}
		})
	}
}
