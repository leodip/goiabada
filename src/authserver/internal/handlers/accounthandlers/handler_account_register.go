package accounthandlers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
	core_user "github.com/leodip/goiabada/core/user"
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
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SelfRegistrationEnabled {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to access self registration page but self registration is not enabled in settings")))
			return
		}

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

		err := emailValidator.ValidateEmailAddress(email)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				renderError(valError.GetDescription())
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
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

		if settings.SMTPEnabled && settings.SelfRegistrationRequiresEmailVerification {
			passwordHash, err := hashutil.HashPassword(password)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			verificationCode := stringutil.GenerateSecureRandomString(32)
			verificationCodeEncrypted, err := encryption.EncryptText(verificationCode, settings.AESEncryptionKey)
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

			auditLogger.Log(constants.AuditCreatedPreRegistration, map[string]interface{}{
				"email": preRegistration.Email,
			})

			bind := map[string]interface{}{
				"link": config.Get().BaseURL + "/account/activate?email=" + email + "&code=" + verificationCode,
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
			passwordHash, err := hashutil.HashPassword(password)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			_, err = userCreator.CreateUser(&core_user.CreateUserInput{
				Email:         email,
				EmailVerified: false,
				PasswordHash:  passwordHash,
			})
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditCreatedUser, map[string]interface{}{
				"email": email,
			})

			if settings.SMTPEnabled {
				bind := map[string]interface{}{
					"link": config.Get().BaseURL + "/account/profile",
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

			http.Redirect(w, r, config.Get().BaseURL+"/auth/pwd", http.StatusFound)
		}
	}
}
