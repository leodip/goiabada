package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleResetPasswordGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", "expecting code to reset the password, but it's empty", http.StatusInternalServerError))
			return
		}

		email := r.URL.Query().Get("email")
		if len(email) == 0 {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", "expecting email to reset the password, but it's empty", http.StatusInternalServerError))
			return
		}

		user, err := s.database.GetUserByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if user == nil {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", fmt.Sprintf("user with email %v does not exist", email), http.StatusInternalServerError))
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		forgotPasswordCode, err := lib.DecryptText(user.ForgotPasswordCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", "unable to decrypt forgot password code", http.StatusInternalServerError))
			return
		}

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		if forgotPasswordCode != code || user.ForgotPasswordCodeIssuedAt.Add(5*time.Minute).Before(time.Now().UTC()) {

			bind["codeInvalidOrExpired"] = true
		}

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/reset_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleResetPasswordPost(passwordValidator passwordValidator) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) error {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/admin_layout.html", "/reset_password.html", bind)
			if err != nil {
				return err
			}
			return nil
		}

		password := r.FormValue("password")
		passwordConfirmation := r.FormValue("passwordConfirmation")

		if len(password) == 0 {
			err := renderError("Password is required.")
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			return
		}

		if password != passwordConfirmation {
			err := renderError("The password confirmation does not match the password.")
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			return
		}

		err := passwordValidator.ValidatePassword(r.Context(), password)
		if err != nil {
			err := renderError(err.Error())
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			return
		}

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", "expecting code to reset the password, but it's empty", http.StatusInternalServerError))
			return
		}

		email := r.URL.Query().Get("email")
		if len(email) == 0 {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", "expecting email to reset the password, but it's empty", http.StatusInternalServerError))
			return
		}

		user, err := s.database.GetUserByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if user == nil {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", fmt.Sprintf("user with email %v does not exist", email), http.StatusInternalServerError))
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		forgotPasswordCode, err := lib.DecryptText(user.ForgotPasswordCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", "unable to decrypt forgot password code", http.StatusInternalServerError))
			return
		}

		if forgotPasswordCode != code {
			s.internalServerError(w, r, customerrors.NewAppError(nil, "", "invalid forgot password code", http.StatusInternalServerError))
			return
		}

		passwordHash, err := lib.HashPassword(password)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user.PasswordHash = passwordHash
		user.ForgotPasswordCodeEncrypted = nil
		user.ForgotPasswordCodeIssuedAt = nil
		_, err = s.database.UpdateUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"passwordReset": true,
		}

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/reset_password.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
