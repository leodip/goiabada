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
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
)

// A request a page sends without a reload is a request of its own, and the console resolves its
// language again from what that request carries. A page opened with ?ui_locales=pt-BR in a browser
// and a profile both in English would then show its dialog's refusals in English, the API's and the
// console's own alike. So each layout publishes the catalog its page rendered from, and every
// request a page script sends names it back as ui_locales, which the locale middleware reads as
// explicit intent the profile's locale does not override (#559 decisions 3 and 7).

// TestRender_LayoutsPublishTheCatalogLanguage holds both layouts to naming the catalog the page
// rendered from, not the first preference asked for: a browser asking for fr-CA first and pt-BR
// third renders pt-BR, and a script naming fr-CA back would get English.
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
			"fr-CA,fr;q=0.9,pt-BR;q=0.8": "pt-BR",
			"en-US":                      "en",
		} {
			t.Run(tc.layout+" "+acceptLanguage, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Accept-Language", acceptLanguage)
				req = req.WithContext(reqctx.WithSettings(req.Context(),
					&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"}))
				w := httptest.NewRecorder()
				var renderErr error
				i18n.Locale(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					renderErr = render.New(web.TemplateFS()).RenderTemplate(w, r, tc.layout, tc.page, tc.bind)
				})).ServeHTTP(w, req)

				require.NoError(t, renderErr)
				assert.Contains(t, w.Body.String(), `data-catalog-lang="`+want+`"`)
			})
		}
	}
}

// TestAjax_ThePagesLanguageOutranksTheBrowserAndTheProfile drives a dialog's save through the
// console's real locale chain, its API client and the permissions handler, in a browser and a
// profile both in English. Named back as ui_locales, the page's pt-BR reaches the API as its
// Accept-Language and the dialog's sentence is Portuguese, the API's refusal and the console's own
// alike; without it, the profile's English wins, which is what the page scripts must not leave to
// chance.
func TestAjax_ThePagesLanguageOutranksTheBrowserAndTheProfile(t *testing.T) {
	for _, tc := range []struct {
		name, target, wantAPILanguage string
		gone                          bool
		status                        int
		code, want                    string
	}{
		{"an API refusal, the page's language named", "/admin/resources/7/permissions?ui_locales=pt-BR", "pt-BR",
			false, http.StatusConflict, "CONCURRENT_UPDATE",
			"A lista foi alterada por outro salvamento depois de ser carregada. Nada foi salvo: recarregue a lista e faça a alteração novamente."},
		{"a console refusal, the page's language named", "/admin/resources/7/permissions?ui_locales=pt-BR", "pt-BR",
			true, http.StatusNotFound, "not_found",
			"Desculpe, não foi possível encontrar o item solicitado. Ele pode ter sido excluído, ou o endereço pode estar incorreto."},
		{"an API refusal, no language named", "/admin/resources/7/permissions", "en",
			false, http.StatusConflict, "CONCURRENT_UPDATE",
			"The list was changed by another save after it was loaded. Nothing was saved: reload it and make the change again."},
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
				handlertest.WithRouteParam("resourceId", "7"),
				handlertest.WithBody(strings.NewReader(`{"resourceId":7,"permissions":[],"expectedPermissions":[]}`)))
			req.Header.Set("Accept-Language", "en")
			w := httptest.NewRecorder()
			handler := adminresourcehandlers.HandlePermissionsPost(render.New(nil), nil,
				apiclient.NewAuthServerClient(upstream.URL, nil))
			i18n.Locale(nil)(middleware.LocaleFromJWT()(handler)).ServeHTTP(w, req)

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
