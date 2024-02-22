package server

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleResetPasswordGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting code to reset the password, but it's empty.")))
			return
		}

		email := r.URL.Query().Get("email")
		if len(email) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting email to reset the password, but it's empty.")))
			return
		}

		user, err := s.databasev2.GetUserByEmail(nil, email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if user == nil {
			s.internalServerError(w, r, errors.WithStack(fmt.Errorf("user with email %v does not exist", email)))
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entitiesv2.Settings)
		forgotPasswordCode, err := lib.DecryptText(user.ForgotPasswordCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, errors.Wrap(err, "unable to decrypt forgot password code"))
			return
		}

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		if forgotPasswordCode != code || user.ForgotPasswordCodeIssuedAt.Time.Add(5*time.Minute).Before(time.Now().UTC()) {

			bind["codeInvalidOrExpired"] = true
		}

		err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleResetPasswordPost(passwordValidator passwordValidator) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
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
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting code to reset the password, but it's empty")))
			return
		}

		email := r.URL.Query().Get("email")
		if len(email) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("expecting email to reset the password, but it's empty")))
			return
		}

		user, err := s.databasev2.GetUserByEmail(nil, email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if user == nil {
			s.internalServerError(w, r, errors.WithStack(fmt.Errorf("user with email %v does not exist", email)))
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entitiesv2.Settings)
		forgotPasswordCode, err := lib.DecryptText(user.ForgotPasswordCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("unable to decrypt forgot password code")))
			return
		}

		if forgotPasswordCode != code {
			s.internalServerError(w, r, errors.WithStack(errors.New("invalid forgot password code")))
			return
		}

		passwordHash, err := lib.HashPassword(password)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user.PasswordHash = passwordHash
		user.ForgotPasswordCodeEncrypted = nil
		user.ForgotPasswordCodeIssuedAt = sql.NullTime{Valid: false}
		err = s.databasev2.UpdateUser(nil, user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"passwordReset": true,
		}

		err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
