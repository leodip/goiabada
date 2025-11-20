package accounthandlers

import (
    "net/http"
    "strings"

    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/pkg/errors"
)

func HandleAccountChangePasswordGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    _ apiclient.ApiClient,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Access token presence ensured by middleware; just handle flash UX
        sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        savedSuccessfully := sess.Flashes("savedSuccessfully")
        if savedSuccessfully != nil {
            if err := httpSession.Save(r, w, sess); err != nil {
                httpHelper.InternalServerError(w, r, err)
                return
            }
        }

        bind := map[string]interface{}{
            "savedSuccessfully": len(savedSuccessfully) > 0,
            "csrfField":         csrf.TemplateField(r),
        }

        if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_change_password.html", bind); err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }
}

func HandleAccountChangePasswordPost(
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

        currentPassword := r.FormValue("currentPassword")
        newPassword := r.FormValue("newPassword")
        newPasswordConfirmation := r.FormValue("newPasswordConfirmation")

        renderError := func(message string) {
            bind := map[string]interface{}{
                "error":     message,
                "csrfField": csrf.TemplateField(r),
            }
            if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_change_password.html", bind); err != nil {
                httpHelper.InternalServerError(w, r, err)
            }
        }

        // UI-level confirmation check only; rest is validated by the API
        if newPassword != newPasswordConfirmation {
            renderError("The new password confirmation does not match the password.")
            return
        }

        req := &api.UpdateAccountPasswordRequest{
            CurrentPassword: strings.TrimSpace(currentPassword),
            NewPassword:     strings.TrimSpace(newPassword),
        }

        _, err := apiClient.UpdateAccountPassword(jwtInfo.TokenResponse.AccessToken, req)
        if err != nil {
            handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
                renderError(errorMessage)
            })
            return
        }

        // Flash success and redirect
        sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
        sess.AddFlash("true", "savedSuccessfully")
        if err := httpSession.Save(r, w, sess); err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }

        http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/change-password", http.StatusFound)
    }
}
