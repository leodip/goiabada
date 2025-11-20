package adminuserhandlers

import (
	"fmt"
	"net/http"
	"strconv"

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

func HandleAdminUserAuthenticationGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
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
		accessToken := jwtInfo.TokenResponse.AccessToken

		user, err := apiClient.GetUserById(accessToken, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
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

		bind := map[string]interface{}{
			"user":              user,
			"otpEnabled":        user.OTPEnabled,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_authentication.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAuthenticationPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
	sessionStore sessions.Store,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
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
		accessToken := jwtInfo.TokenResponse.AccessToken

		user, err := apiClient.GetUserById(accessToken, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"user":       user,
				"otpEnabled": r.FormValue("otpEnabled") == "on",
				"page":       r.URL.Query().Get("page"),
				"query":      r.URL.Query().Get("query"),
				"csrfField":  csrf.TemplateField(r),
				"error":      message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_authentication.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		hasDisabledOTP := false

		// Handle password update
		newPassword := r.FormValue("newPassword")
		if len(newPassword) > 0 {
			passwordReq := &api.UpdateUserPasswordRequest{
				NewPassword: newPassword,
			}
			_, err := apiClient.UpdateUserPassword(accessToken, id, passwordReq)
			if err != nil {
				// Check if it's a validation error
				if apiErr, ok := err.(*apiclient.APIError); ok && apiErr.StatusCode == 400 {
					renderError(apiErr.Message)
					return
				}
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		// Handle OTP toggle
		if user.OTPEnabled {
			otpEnabled := r.FormValue("otpEnabled") == "on"
			if !otpEnabled {
				otpReq := &api.UpdateUserOTPRequest{
					Enabled: false,
				}
				_, err := apiClient.UpdateUserOTP(accessToken, id, otpReq)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				hasDisabledOTP = true
			}
		}

		// Handle session update when OTP is disabled
		if hasDisabledOTP {
			sess, err := sessionStore.Get(r, constants.AdminConsoleSessionName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			if sess.Values[constants.SessionKeySessionIdentifier] != nil {
				sessionIdentifier := sess.Values[constants.SessionKeySessionIdentifier].(string)
				level2Changed := true
				sessionReq := &api.UpdateUserSessionRequest{
					Level2AuthConfigHasChanged: &level2Changed,
				}
				_, _ = apiClient.UpdateUserSession(accessToken, sessionIdentifier, sessionReq)
				// Continue even if session update fails - it's not critical
			}
		}

		// Set success flash
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

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/authentication?page=%v&query=%v", config.GetAdminConsole().BaseURL, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
