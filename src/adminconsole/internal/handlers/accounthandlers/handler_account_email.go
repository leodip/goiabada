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
    "github.com/leodip/goiabada/core/models"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/pkg/errors"
)

func HandleAccountEmailGet(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

        // Get JWT info to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
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

        settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		bind := map[string]interface{}{
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"email":             user.Email,
			"emailVerified":     user.EmailVerified,
			"emailConfirmation": "",
			"smtpEnabled":       settings.SMTPEnabled,
			"csrfField":         csrf.TemplateField(r),
		}

        err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
    }
}

func HandleAccountEmailPost(
    httpHelper handlers.HttpHelper,
    httpSession sessions.Store,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {

        // Get JWT info and current user for re-render on error
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        user, err := apiClient.GetAccountProfile(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

        email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
        emailConfirmation := strings.ToLower(strings.TrimSpace(r.FormValue("emailConfirmation")))

        // UI-level confirmation check
        if email != emailConfirmation {
            bind := map[string]interface{}{
                "user":              user,
                "email":             email,
                "emailVerified":     user.EmailVerified,
                "emailConfirmation": emailConfirmation,
                "csrfField":         csrf.TemplateField(r),
                "error":             "The email and email confirmation entries must be identical.",
            }
            if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind); err != nil {
                httpHelper.InternalServerError(w, r, err)
            }
            return
        }

        req := &api.UpdateAccountEmailRequest{Email: email}
        _, err = apiClient.UpdateAccountEmail(jwtInfo.TokenResponse.AccessToken, req)
        if err != nil {
            handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(errorMessage string) {
                bind := map[string]interface{}{
                    "user":              user,
                    "email":             email,
                    "emailVerified":     user.EmailVerified,
                    "emailConfirmation": emailConfirmation,
                    "csrfField":         csrf.TemplateField(r),
                    "error":             errorMessage,
                }
                if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind); err != nil {
                    httpHelper.InternalServerError(w, r, err)
                }
            })
            return
        }

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

        http.Redirect(w, r, config.GetAdminConsole().BaseURL+"/account/email", http.StatusFound)
    }
}
