package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
)

func HandleResetPasswordGet(
	httpHelper HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code to reset the password, but it's empty.")))
			return
		}

		email := r.URL.Query().Get("email")
		if len(email) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting email to reset the password, but it's empty.")))
			return
		}

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("user with email %v does not exist", email)))
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		forgotPasswordCode, err := encryption.DecryptText(user.ForgotPasswordCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "unable to decrypt forgot password code"))
			return
		}

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		if forgotPasswordCode != code || user.ForgotPasswordCodeIssuedAt.Time.Add(5*time.Minute).Before(time.Now().UTC()) {

			bind["codeInvalidOrExpired"] = true
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleResetPasswordPost(
	httpHelper HttpHelper,
	database data.Database,
	passwordValidator PasswordValidator,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		password := r.FormValue("password")
		passwordConfirmation := r.FormValue("passwordConfirmation")

		if len(password) == 0 {
			renderError("Password is required.")
			return
		}

		if password != passwordConfirmation {
			renderError("The password confirmation does not match the password.")
			return
		}

		err := passwordValidator.ValidatePassword(r.Context(), password)
		if err != nil {
			renderError(err.Error())
			return
		}

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code to reset the password, but it's empty")))
			return
		}

		email := r.URL.Query().Get("email")
		if len(email) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting email to reset the password, but it's empty")))
			return
		}

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("user with email %v does not exist", email)))
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		forgotPasswordCode, err := encryption.DecryptText(user.ForgotPasswordCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to decrypt forgot password code")))
			return
		}

		if forgotPasswordCode != code {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("invalid forgot password code")))
			return
		}

		passwordHash, err := hashutil.HashPassword(password)
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

		bind := map[string]interface{}{
			"passwordReset":       true,
			"adminConsoleBaseUrl": config.GetAdminConsole().BaseURL,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
