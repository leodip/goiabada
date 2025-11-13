package adminclienthandlers

import (
    "fmt"
    "net/http"
    "strconv"
    "strings"

    "github.com/pkg/errors"

    "github.com/go-chi/chi/v5"
    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
)

func HandleAdminClientTokensGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

        id, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        client, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }
        if client == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

        settingsInfo := struct {
            TokenExpirationInSeconds                int
            RefreshTokenOfflineIdleTimeoutInSeconds int
            RefreshTokenOfflineMaxLifetimeInSeconds int
            IncludeOpenIDConnectClaimsInAccessToken string
        }{
            TokenExpirationInSeconds:                client.TokenExpirationInSeconds,
            RefreshTokenOfflineIdleTimeoutInSeconds: client.RefreshTokenOfflineIdleTimeoutInSeconds,
            RefreshTokenOfflineMaxLifetimeInSeconds: client.RefreshTokenOfflineMaxLifetimeInSeconds,
            IncludeOpenIDConnectClaimsInAccessToken: client.IncludeOpenIDConnectClaimsInAccessToken,
        }

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"settings":          settingsInfo,
			"client":            client,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

        err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }
}

func HandleAdminClientTokensPost(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

        id, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        client, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }
        if client == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

        settingsInfo := struct {
            TokenExpirationInSeconds                string
            RefreshTokenOfflineIdleTimeoutInSeconds string
            RefreshTokenOfflineMaxLifetimeInSeconds string
            IncludeOpenIDConnectClaimsInAccessToken string
        }{
            TokenExpirationInSeconds:                strings.TrimSpace(r.FormValue("tokenExpirationInSeconds")),
            RefreshTokenOfflineIdleTimeoutInSeconds: strings.TrimSpace(r.FormValue("refreshTokenOfflineIdleTimeoutInSeconds")),
            RefreshTokenOfflineMaxLifetimeInSeconds: strings.TrimSpace(r.FormValue("refreshTokenOfflineMaxLifetimeInSeconds")),
            IncludeOpenIDConnectClaimsInAccessToken: strings.TrimSpace(r.FormValue("includeOpenIDConnectClaimsInAccessToken")),
        }

		renderError := func(message string) {

			bind := map[string]interface{}{
				"settings":  settingsInfo,
				"client":    client,
				"csrfField": csrf.TemplateField(r),
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_tokens.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

        tokenExpirationInSeconds, err := strconv.Atoi(settingsInfo.TokenExpirationInSeconds)
        if err != nil {
            settingsInfo.TokenExpirationInSeconds = strconv.Itoa(client.TokenExpirationInSeconds)
            renderError("Invalid value for token expiration in seconds.")
            return
        }

        refreshTokenOfflineIdleTimeoutInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds)
        if err != nil {
            settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds = strconv.Itoa(client.RefreshTokenOfflineIdleTimeoutInSeconds)
            renderError("Invalid value for refresh token offline - idle timeout in seconds.")
            return
        }

        refreshTokenOfflineMaxLifetimeInSeconds, err := strconv.Atoi(settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds)
        if err != nil {
            settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds = strconv.Itoa(client.RefreshTokenOfflineMaxLifetimeInSeconds)
            renderError("Invalid value for refresh token offline - max lifetime in seconds.")
            return
        }

        updateReq := &api.UpdateClientTokensRequest{
            TokenExpirationInSeconds:                tokenExpirationInSeconds,
            RefreshTokenOfflineIdleTimeoutInSeconds: refreshTokenOfflineIdleTimeoutInSeconds,
            RefreshTokenOfflineMaxLifetimeInSeconds: refreshTokenOfflineMaxLifetimeInSeconds,
            IncludeOpenIDConnectClaimsInAccessToken: settingsInfo.IncludeOpenIDConnectClaimsInAccessToken,
        }

        _, err = apiClient.UpdateClientTokens(jwtInfo.TokenResponse.AccessToken, id, updateReq)
        if err != nil {
            handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
            return
        }

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

        http.Redirect(w, r, fmt.Sprintf("%v/admin/clients/%v/tokens", config.GetAdminConsole().BaseURL, client.Id), http.StatusFound)
    }
}
