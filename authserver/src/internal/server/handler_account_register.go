package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core_senders "github.com/leodip/goiabada/internal/core/senders"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountRegisterGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		if !settings.SelfRegistrationEnabled {
			s.internalServerError(w, r, errors.New("trying to access self registration page but self registration is not enabled in settings"))
			return
		}

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := s.renderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountRegisterPost(emailValidator emailValidator,
	passwordValidator passwordValidator, emailSender emailSender) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		password := r.FormValue("password")
		passwordConfirmation := r.FormValue("passwordConfirmation")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"email":     email,
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if len(email) == 0 {
			renderError("Email is required.")
			return
		}

		err := emailValidator.ValidateEmailAddress(r.Context(), email)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				renderError(valError.Description)
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		alreadyRegisteredMessage := "Apologies, but this email address is already registered."

		user, err := s.database.GetUserByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		preRegistration, err := s.database.GetPreRegistrationByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if preRegistration != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		if len(password) == 0 {
			renderError("Password is required.")
			return
		}

		if len(password) > 0 && len(passwordConfirmation) == 0 {
			renderError("Password confirmation is required.")
			return
		}

		if password != passwordConfirmation {
			renderError("The password confirmation does not match the password.")
			return
		}

		err = passwordValidator.ValidatePassword(r.Context(), password)
		if err != nil {
			renderError(err.Error())
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		if !settings.SelfRegistrationEnabled {
			s.internalServerError(w, r, errors.New("trying to access self registration page but self registration is not enabled in settings"))
			return
		}

		if settings.SelfRegistrationRequiresEmailVerification {
			passwordHash, err := lib.HashPassword(password)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			verificationCode := lib.GenerateSecureRandomString(32)
			verificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			utcNow := time.Now().UTC()
			preRegistration := &entities.PreRegistration{
				Email:                     email,
				PasswordHash:              passwordHash,
				VerificationCodeEncrypted: verificationCodeEncrypted,
				VerificationCodeIssuedAt:  &utcNow,
			}

			_, err = s.database.SavePreRegistration(preRegistration)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			bind := map[string]interface{}{
				"link": lib.GetBaseUrl() + "/account/activate?email=" + email + "&code=" + verificationCode,
			}
			buf, err := s.renderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_register_activate.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			input := &core_senders.SendEmailInput{
				To:       email,
				Subject:  "Activate your account",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			bind = map[string]interface{}{
				"email":     email,
				"csrfField": csrf.TemplateField(r),
			}

			err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		} else {
			passwordHash, err := lib.HashPassword(password)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			newUser := &entities.User{
				Subject:      uuid.New(),
				Email:        email,
				PasswordHash: passwordHash,
			}

			_, err = s.database.SaveUser(newUser)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			bind := map[string]interface{}{
				"link": lib.GetBaseUrl() + "/account/profile",
			}
			buf, err := s.renderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_register_confirmation.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			input := &core_senders.SendEmailInput{
				To:       email,
				Subject:  "Welcome!",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			http.Redirect(w, r, lib.GetBaseUrl()+"/auth/pwd", http.StatusFound)
		}
	}
}
