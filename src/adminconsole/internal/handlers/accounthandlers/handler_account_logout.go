package accounthandlers

import (
    "net/http"

    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/leodip/goiabada/core/stringutil"
)

func HandleAccountLogoutGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {
        var jwtInfo oauth.JwtInfo
        if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
            jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        }

        session, err := httpSession.Get(r, constants.AdminConsoleSessionName)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        // Clear the local session
        session.Options.MaxAge = -1
        if err = httpSession.Save(r, w, session); err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        // If we don't have a valid ID token, just go back to the console home
        if jwtInfo.IdToken == nil || jwtInfo.AccessToken == nil {
            http.Redirect(w, r, config.GetAdminConsole().BaseURL, http.StatusFound)
            return
        }

        // Build logout request via API (form_post preferred to avoid URL token leak)
        accessToken := jwtInfo.AccessToken.TokenBase64
        req := &api.AccountLogoutRequest{
            PostLogoutRedirectUri: config.GetAdminConsole().BaseURL,
            State:                 stringutil.GenerateSecurityRandomString(32),
            ResponseMode:          "redirect",
        }

        _, redirectResp, err := apiClient.CreateAccountLogoutRequest(accessToken, req)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
        // Always use redirect mode
        http.Redirect(w, r, redirectResp.LogoutUrl, http.StatusFound)
    }
}
