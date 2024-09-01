package accounthandlers

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAccountChangePasswordGet(httpHelper handlers.HttpHelper) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_change_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountChangePasswordPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	passwordValidator handlers.PasswordValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		currentPassword := r.FormValue("currentPassword")
		newPassword := r.FormValue("newPassword")
		newPasswordConfirmation := r.FormValue("newPasswordConfirmation")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_change_password.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if len(strings.TrimSpace(currentPassword)) == 0 {
			renderError("Current password is required.")
			return
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if !hashutil.VerifyPasswordHash(user.PasswordHash, currentPassword) {
			renderError("Authentication failed. Check your current password and try again.")
			return
		}

		if len(strings.TrimSpace(newPassword)) == 0 {
			renderError("New password is required.")
			return
		}

		if newPassword != newPasswordConfirmation {
			renderError("The new password confirmation does not match the password.")
			return
		}

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
		err = database.UpdateUser(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditChangedPassword, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		bind := map[string]interface{}{
			"savedSuccessfully": true,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_change_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}