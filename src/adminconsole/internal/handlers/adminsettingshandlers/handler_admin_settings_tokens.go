package adminsettingshandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/sessionstore"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
)

// settingsTokensAPI is what the token settings page needs: the settings, and the write.
type settingsTokensAPI interface {
	GetSettingsTokens(ctx context.Context, accessToken string) (*api.SettingsTokensResponse, error)
	UpdateSettingsTokens(ctx context.Context, accessToken string, request *api.UpdateSettingsTokensRequest) (*api.SettingsTokensResponse, error)
}

func HandleTokensGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsTokensAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Fetch settings from API
		apiResp, err := apiClient.GetSettingsTokens(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsInfo := SettingsTokenGet{
			TokenExpirationInSeconds:                apiResp.TokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: apiResp.RefreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: apiResp.RefreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: apiResp.IncludeOpenIDConnectClaimsInAccessToken,
			IncludeOpenIDConnectClaimsInIdToken:     apiResp.IncludeOpenIDConnectClaimsInIdToken,
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleTokensPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient settingsTokensAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		settingsInfo := SettingsTokenPost{
			TokenExpirationInSeconds:                r.FormValue("tokenExpirationInSeconds"),
			RefreshTokenOfflineIdleTimeoutInSeconds: r.FormValue("refreshTokenOfflineIdleTimeoutInSeconds"),
			RefreshTokenOfflineMaxLifetimeInSeconds: r.FormValue("refreshTokenOfflineMaxLifetimeInSeconds"),
			IncludeOpenIDConnectClaimsInAccessToken: r.FormValue("includeOpenIDConnectClaimsInAccessToken") == "on",
			IncludeOpenIDConnectClaimsInIdToken:     r.FormValue("includeOpenIDConnectClaimsInIdToken") == "on",
		}

		renderError := func(message, errorField string) {
			bind := map[string]interface{}{
				"settings":   settingsInfo,
				"error":      message,
				"errorField": errorField,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// A duration that is not a whole number is refused here, at its field, rather than sent as
		// 0, which the auth server would refuse as not greater than zero.
		tokenExp, err := strconv.Atoi(strings.TrimSpace(settingsInfo.TokenExpirationInSeconds))
		if err != nil {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.settings_tokens.token_expiration_invalid"), "tokenExpirationInSeconds")
			return
		}
		idle, err := strconv.Atoi(strings.TrimSpace(settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds))
		if err != nil {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.settings_tokens.offline_idle_timeout_invalid"), "refreshTokenOfflineIdleTimeoutInSeconds")
			return
		}
		maxlife, err := strconv.Atoi(strings.TrimSpace(settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds))
		if err != nil {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.settings_tokens.offline_max_lifetime_invalid"), "refreshTokenOfflineMaxLifetimeInSeconds")
			return
		}

		updateReq := &api.UpdateSettingsTokensRequest{
			TokenExpirationInSeconds:                tokenExp,
			RefreshTokenOfflineIdleTimeoutInSeconds: idle,
			RefreshTokenOfflineMaxLifetimeInSeconds: maxlife,
			IncludeOpenIDConnectClaimsInAccessToken: settingsInfo.IncludeOpenIDConnectClaimsInAccessToken,
			IncludeOpenIDConnectClaimsInIdToken:     settingsInfo.IncludeOpenIDConnectClaimsInIdToken,
		}

		_, err = apiClient.UpdateSettingsTokens(r.Context(), jwtInfo.TokenResponse.AccessToken, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, tokensErrorFields))
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/tokens", baseURL), http.StatusFound)
	}
}
