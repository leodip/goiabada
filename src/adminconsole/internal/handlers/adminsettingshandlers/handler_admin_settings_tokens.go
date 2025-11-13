package adminsettingshandlers

import (
    "fmt"
    "net/http"
    "strconv"

    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/pkg/errors"

    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
)

func HandleAdminSettingsTokensGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {

        // Get access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        // Fetch settings from API
        apiResp, err := apiClient.GetSettingsTokens(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

        settingsInfo := SettingsTokenGet{
            TokenExpirationInSeconds:                apiResp.TokenExpirationInSeconds,
            RefreshTokenOfflineIdleTimeoutInSeconds: apiResp.RefreshTokenOfflineIdleTimeoutInSeconds,
            RefreshTokenOfflineMaxLifetimeInSeconds: apiResp.RefreshTokenOfflineMaxLifetimeInSeconds,
            IncludeOpenIDConnectClaimsInAccessToken: apiResp.IncludeOpenIDConnectClaimsInAccessToken,
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
            "savedSuccessfully": len(savedSuccessfully) > 0,
            "csrfField":         csrf.TemplateField(r),
        }

        err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }
}

func HandleAdminSettingsTokensPost(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {

        // Get access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        settingsInfo := SettingsTokenPost{
            TokenExpirationInSeconds:                r.FormValue("tokenExpirationInSeconds"),
            RefreshTokenOfflineIdleTimeoutInSeconds: r.FormValue("refreshTokenOfflineIdleTimeoutInSeconds"),
            RefreshTokenOfflineMaxLifetimeInSeconds: r.FormValue("refreshTokenOfflineMaxLifetimeInSeconds"),
            IncludeOpenIDConnectClaimsInAccessToken: r.FormValue("includeOpenIDConnectClaimsInAccessToken") == "on",
        }

        renderError := func(message string) {
            bind := map[string]interface{}{
                "settings":  settingsInfo,
                "csrfField": csrf.TemplateField(r),
                "error":     message,
            }

            err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_tokens.html", bind)
            if err != nil {
                httpHelper.InternalServerError(w, r, err)
            }
        }

        // Prepare request with ints; invalid input becomes 0 to trigger server-side validation
        tokenExp := 0
        if v := settingsInfo.TokenExpirationInSeconds; len(v) > 0 {
            if p, err := strconv.Atoi(v); err == nil {
                tokenExp = p
            }
        }
        idle := 0
        if v := settingsInfo.RefreshTokenOfflineIdleTimeoutInSeconds; len(v) > 0 {
            if p, err := strconv.Atoi(v); err == nil {
                idle = p
            }
        }
        maxlife := 0
        if v := settingsInfo.RefreshTokenOfflineMaxLifetimeInSeconds; len(v) > 0 {
            if p, err := strconv.Atoi(v); err == nil {
                maxlife = p
            }
        }

        updateReq := &api.UpdateSettingsTokensRequest{
            TokenExpirationInSeconds:                tokenExp,
            RefreshTokenOfflineIdleTimeoutInSeconds: idle,
            RefreshTokenOfflineMaxLifetimeInSeconds: maxlife,
            IncludeOpenIDConnectClaimsInAccessToken: settingsInfo.IncludeOpenIDConnectClaimsInAccessToken,
        }

        _, err := apiClient.UpdateSettingsTokens(jwtInfo.TokenResponse.AccessToken, updateReq)
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

        http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/tokens", config.GetAdminConsole().BaseURL), http.StatusFound)
    }
}
