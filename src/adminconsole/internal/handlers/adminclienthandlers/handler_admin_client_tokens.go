package adminclienthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// clientTokensAPI is what the client tokens page needs: the client, the global token settings each
// of its "use the global setting" choices names the value of, the token settings write, and the
// write of "Require DPoP for token requests", which the auth server keeps on a route of its own.
type clientTokensAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	GetSettingsTokens(ctx context.Context, accessToken string) (*api.SettingsTokensResponse, error)
	UpdateClientTokens(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientTokensRequest) (*api.ClientResponse, error)
	UpdateClientDPoP(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientDPoPRequest) (*api.ClientResponse, error)
}

// clientTokens is what the Tokens tab's inputs show: the client as stored on a first draw, or as
// submitted when a refused save is drawn again, a duration that is not a number included.
//
// DPoPBoundAccessTokens is "Require DPoP for token requests" (#42 decisions 12 and 13), a switch of
// the tab's one form, saved by its one Save: HandleTokensPost writes it through the auth server's
// route for it, PUT /clients/{id}/dpop, and only when it changed, as the Settings tab writes its
// administrative scopes allowance (#542). The admin console's own client, the system-level one, is
// not offered it: the tab draws no switch for it, and its save never writes it.
type clientTokens struct {
	TokenExpirationInSeconds                string
	RefreshTokenOfflineIdleTimeoutInSeconds string
	RefreshTokenOfflineMaxLifetimeInSeconds string
	IncludeOpenIDConnectClaimsInAccessToken string
	IncludeOpenIDConnectClaimsInIdToken     string
	DPoPBoundAccessTokens                   bool
}

// clientTokensFrom draws the Tokens tab from the client as the auth server answers it.
func clientTokensFrom(c *api.ClientResponse) clientTokens {
	return clientTokens{
		TokenExpirationInSeconds:                strconv.Itoa(c.TokenExpirationInSeconds),
		RefreshTokenOfflineIdleTimeoutInSeconds: strconv.Itoa(c.RefreshTokenOfflineIdleTimeoutInSeconds),
		RefreshTokenOfflineMaxLifetimeInSeconds: strconv.Itoa(c.RefreshTokenOfflineMaxLifetimeInSeconds),
		IncludeOpenIDConnectClaimsInAccessToken: c.IncludeOpenIDConnectClaimsInAccessToken,
		IncludeOpenIDConnectClaimsInIdToken:     c.IncludeOpenIDConnectClaimsInIdToken,
		DPoPBoundAccessTokens:                   c.DPoPBoundAccessTokens,
	}
}

func HandleTokensGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientTokensAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		client, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		settingsInfo := clientTokensFrom(client)

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash(r.URL.Path, "savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		global, err := apiClient.GetSettingsTokens(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"client":            client,
			"global":            global,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// HandleTokensPost saves the Tokens tab: the token settings through the client's tokens route, then
// "Require DPoP for token requests" through its own route when the switch differs from the stored
// requirement. The switch is read from the body alone: a browser submits an unticked checkbox as
// nothing, so its absence means off, a value in the query is no submission of this form, and only
// the checkbox's own value switches it on. The admin console's own client keeps its stored
// requirement whatever the body says.
//
// The two writes are two requests, so a refused requirement leaves the token settings saved: the tab
// is drawn again from the client as it now stands, saying the settings were saved, with the refusal
// beside the switch.
func HandleTokensPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientTokensAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		client, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		requireDPoP := r.PostFormValue("dpopBoundAccessTokens") == "on"
		if client.IsSystemLevelClient {
			requireDPoP = client.DPoPBoundAccessTokens
		}

		settingsInfo := clientTokens{
			TokenExpirationInSeconds:                strings.TrimSpace(r.FormValue("tokenExpirationInSeconds")),
			RefreshTokenOfflineIdleTimeoutInSeconds: strings.TrimSpace(r.FormValue("refreshTokenOfflineIdleTimeoutInSeconds")),
			RefreshTokenOfflineMaxLifetimeInSeconds: strings.TrimSpace(r.FormValue("refreshTokenOfflineMaxLifetimeInSeconds")),
			IncludeOpenIDConnectClaimsInAccessToken: strings.TrimSpace(r.FormValue("includeOpenIDConnectClaimsInAccessToken")),
			IncludeOpenIDConnectClaimsInIdToken:     strings.TrimSpace(r.FormValue("includeOpenIDConnectClaimsInIdToken")),
			DPoPBoundAccessTokens:                   requireDPoP,
		}

		// A refused save draws every input as submitted, a duration that is not a number and both
		// choices included; the title comes from the stored client, and the global values the choices
		// name from the global settings.
		renderError := func(message, errorField string) {
			global, globalErr := apiClient.GetSettingsTokens(r.Context(), jwtInfo.TokenResponse.AccessToken)
			if globalErr != nil {
				render.HandleAPIError(httpHelper, w, r, globalErr)
				return
			}

			bind := map[string]interface{}{
				"settings":   settingsInfo,
				"client":     client,
				"global":     global,
				"error":      message,
				"errorField": errorField,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		tokenExpirationInSeconds, err := strconv.Atoi(settingsInfo.TokenExpirationInSeconds)
		if err != nil {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.client_tokens.token_expiration_invalid"), "tokenExpirationInSeconds")
			return
		}

		refreshTokenOfflineIdleTimeoutInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds)
		if err != nil {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.client_tokens.offline_idle_timeout_invalid"), "refreshTokenOfflineIdleTimeoutInSeconds")
			return
		}

		refreshTokenOfflineMaxLifetimeInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds)
		if err != nil {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.client_tokens.offline_max_lifetime_invalid"), "refreshTokenOfflineMaxLifetimeInSeconds")
			return
		}

		updateReq := &api.UpdateClientTokensRequest{
			TokenExpirationInSeconds:                tokenExpirationInSeconds,
			RefreshTokenOfflineIdleTimeoutInSeconds: refreshTokenOfflineIdleTimeoutInSeconds,
			RefreshTokenOfflineMaxLifetimeInSeconds: refreshTokenOfflineMaxLifetimeInSeconds,
			IncludeOpenIDConnectClaimsInAccessToken: settingsInfo.IncludeOpenIDConnectClaimsInAccessToken,
			IncludeOpenIDConnectClaimsInIdToken:     settingsInfo.IncludeOpenIDConnectClaimsInIdToken,
		}

		updated, err := apiClient.UpdateClientTokens(r.Context(), jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, clientTokensErrorFields))
			})
			return
		}

		if requireDPoP != client.DPoPBoundAccessTokens {
			renderDPoPError := func(message string) {
				stored := client
				if updated != nil {
					stored = updated
				}
				global, globalErr := apiClient.GetSettingsTokens(r.Context(), jwtInfo.TokenResponse.AccessToken)
				if globalErr != nil {
					render.HandleAPIError(httpHelper, w, r, globalErr)
					return
				}
				bind := map[string]interface{}{
					"settings":          clientTokensFrom(stored),
					"client":            stored,
					"global":            global,
					"savedSuccessfully": true,
					"dpopError":         message,
				}
				renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
				if renderErr != nil {
					httpHelper.InternalServerError(w, r, renderErr)
				}
			}
			_, err = apiClient.UpdateClientDPoP(r.Context(), jwtInfo.TokenResponse.AccessToken, id,
				&api.UpdateClientDPoPRequest{DPoPBoundAccessTokens: &requireDPoP})
			if err != nil {
				render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderDPoPError)
				return
			}
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		pagePath := fmt.Sprintf("/admin/clients/%v/tokens", client.Id)
		sess.SetFlash(pagePath, "savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, baseURL+pagePath, http.StatusFound)
	}
}
