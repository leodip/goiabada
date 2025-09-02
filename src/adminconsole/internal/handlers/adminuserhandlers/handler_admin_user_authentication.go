package adminuserhandlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/hashutil"
)

func HandleAdminUserAuthenticationGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
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
		user, err := database.GetUserById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
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
	authHelper handlers.AuthHelper,
	database data.Database,
	passwordValidator handlers.PasswordValidator,
	sessionStore sessions.Store,
	auditLogger handlers.AuditLogger,
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
		user, err := database.GetUserById(nil, id)
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

		hasUpdatedPassword := false

		newPassword := r.FormValue("newPassword")
		if len(newPassword) > 0 {
			err = passwordValidator.ValidatePassword(r.Context(), newPassword)
			if err != nil {
				renderError(err.Error())
				return
			}

			passwordHash, err := hashutil.HashPassword(newPassword)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			user.PasswordHash = passwordHash
			user.ForgotPasswordCodeEncrypted = nil
			user.ForgotPasswordCodeIssuedAt = sql.NullTime{Valid: false}

			hasUpdatedPassword = true
		}

		hasDisabledOTP := false

		if user.OTPEnabled {
			otpEnabled := r.FormValue("otpEnabled") == "on"
			if !otpEnabled {
				user.OTPEnabled = false
				user.OTPSecret = ""
				hasDisabledOTP = true
			}
		}

		if hasUpdatedPassword || hasDisabledOTP {
			err = database.UpdateUser(nil, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		if hasDisabledOTP {

			auditLogger.Log(constants.AuditDisabledOTP, map[string]interface{}{
				"userId": user.Id,
			})

			// update session to flag a level 2 auth method configuration has changed
			// this is important when deciding whether to prompt the user to authenticate with level 2 methods

			sess, err := sessionStore.Get(r, constants.SessionName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			if sess.Values[constants.SessionKeySessionIdentifier] == nil {
				httpHelper.InternalServerError(w, r, fmt.Errorf("session identifier not found"))
				return
			}

			sessionIdentifier := sess.Values[constants.SessionKeySessionIdentifier].(string)
			userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			userSession.Level2AuthConfigHasChanged = true

			err = database.UpdateUserSession(nil, userSession)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		sess, err := httpSession.Get(r, constants.SessionName)
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

		if hasUpdatedPassword {
			auditLogger.Log(constants.AuditUpdatedUserAuthentication, map[string]interface{}{
				"userId":       user.Id,
				"loggedInUser": authHelper.GetLoggedInSubject(r),
			})
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/authentication?page=%v&query=%v", config.GetAdminConsole().BaseURL, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
