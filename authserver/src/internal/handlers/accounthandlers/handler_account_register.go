package accounthandlers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/communication"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/users"
)

func HandleAccountRegisterGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SelfRegistrationEnabled {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to access self registration page but self registration is not enabled in settings")))
			return
		}

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountRegisterPost(
	httpHelper handlers.HttpHelper,
	database data.Database,
	userCreator handlers.UserCreator,
	emailValidator handlers.EmailValidator,
	passwordValidator handlers.PasswordValidator,
	emailSender handlers.EmailSender,
) http.HandlerFunc {

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

			err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
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
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		alreadyRegisteredMessage := "Apologies, but this email address is already registered."

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		preRegistration, err := database.GetPreRegistrationByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
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

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SelfRegistrationEnabled {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to access self registration page but self registration is not enabled in settings")))
			return
		}

		if settings.SMTPEnabled && settings.SelfRegistrationRequiresEmailVerification {
			passwordHash, err := lib.HashPassword(password)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			verificationCode := lib.GenerateSecureRandomString(32)
			verificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			utcNow := time.Now().UTC()
			preRegistration := &models.PreRegistration{
				Email:                     email,
				PasswordHash:              passwordHash,
				VerificationCodeEncrypted: verificationCodeEncrypted,
				VerificationCodeIssuedAt:  sql.NullTime{Time: utcNow, Valid: true},
			}

			err = database.CreatePreRegistration(nil, preRegistration)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditCreatedPreRegistration, map[string]interface{}{
				"email": preRegistration.Email,
			})

			bind := map[string]interface{}{
				"link": lib.GetBaseUrl() + "/account/activate?email=" + email + "&code=" + verificationCode,
			}
			buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_register_activate.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			input := &communication.SendEmailInput{
				To:       email,
				Subject:  "Activate your account",
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			bind = map[string]interface{}{
				"email":     email,
				"csrfField": csrf.TemplateField(r),
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		} else {
			passwordHash, err := lib.HashPassword(password)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			_, err = userCreator.CreateUser(r.Context(), &users.CreateUserInput{
				Email:         email,
				EmailVerified: false,
				PasswordHash:  passwordHash,
			})
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditCreatedUser, map[string]interface{}{
				"email": email,
			})

			if settings.SMTPEnabled {
				bind := map[string]interface{}{
					"link": lib.GetBaseUrl() + "/account/profile",
				}
				buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_register_confirmation.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}

				input := &communication.SendEmailInput{
					To:       email,
					Subject:  "Welcome!",
					HtmlBody: buf.String(),
				}
				err = emailSender.SendEmail(r.Context(), input)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			}

			http.Redirect(w, r, lib.GetBaseUrl()+"/auth/pwd", http.StatusFound)
		}
	}
}
