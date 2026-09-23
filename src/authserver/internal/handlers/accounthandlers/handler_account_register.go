package accounthandlers

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/stringutil"
)

// refuseSelfRegistrationDisabled answers a self-registration page, or an activation link, while
// the setting is off: one Warn record and the not-found page.
//
// 404 is RFC 9110 section 15.5.5's status for a resource the server "is not willing to disclose
// that one exists", which is what a feature switched off is. It used to be the 500 page with an
// error-level stack, which alerted an operator for every visitor following an old link to a page
// the operator had turned off on purpose (#425 decision 5).
func refuseSelfRegistrationDisabled(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) {
	slog.WarnContext(r.Context(), "self-registration request refused because self-registration is disabled")
	httpHelper.NotFound(w, r)
}

func HandleAccountRegisterGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(httpHelper, w, r)
			return
		}

		bind := map[string]interface{}{}

		err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// accountRegisterDatabase is what the self-registration page needs: the address it must not
// duplicate, and the pre-registration it parks.
type accountRegisterDatabase interface {
	CreatePreRegistration(ctx context.Context, tx *sql.Tx, preRegistration *models.PreRegistration) error
	GetPreRegistrationByEmail(ctx context.Context, tx *sql.Tx, email string) (*models.PreRegistration, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*models.User, error)
}

func HandleAccountRegisterPost(
	httpHelper HttpHelper,
	database accountRegisterDatabase,
	userCreator UserCreator,
	emailValidator EmailValidator,
	passwordValidator PasswordValidator,
	emailSender EmailSender,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(httpHelper, w, r)
			return
		}

		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		// r.PostFormValue rather than r.FormValue: r.Form merges the URL query behind the
		// body, so /account/register?password=... would register an account with a password
		// taken from a request target, where it reaches the browser's history, the Referer of
		// anything the page loads, and the access log of every proxy in front of the
		// deployment. Only the submitted body is a submission (#202). The email read above
		// keeps the merged accessor: it is not a credential, and the rate limiter derives its
		// per-account key from the same accessor, so the two must not diverge (#219).
		password := r.PostFormValue("password")
		passwordConfirmation := r.PostFormValue("passwordConfirmation")

		renderError := func(message string) {
			bind := map[string]interface{}{
				"email": email,
				"error": message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if len(email) == 0 {
			// i18n surface: A — browser-flow form rerender.
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerEmailRequired, nil).Localize(r.Context()))
			return
		}

		err := emailValidator.ValidateEmailAddress(email)
		if err != nil {
			// i18n surface: A — browser-flow form rerender.
			// errors.As in the switch's own order, not a type switch: both read the dynamic type,
			// so anything that wrapped the validator's result on the way here would fall through
			// to default and answer a 500 page rather than redrawing the form with the reason
			// (#279 decision 6).
			var localizedErr *i18n.LocalizedError
			var errorDetail *customerrors.ErrorDetail
			switch {
			case errors.As(err, &localizedErr):
				renderError(localizedErr.Localize(r.Context()))
			case errors.As(err, &errorDetail):
				renderError(errorDetail.GetDescription())
			default:
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		alreadyRegisteredMessage := i18n.NewLocalizedError(i18n.ErrCodeEmailAlreadyRegistered, nil).Localize(r.Context())

		user, err := database.GetUserByEmail(r.Context(), nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		preRegistration, err := database.GetPreRegistrationByEmail(r.Context(), nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if preRegistration != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		// i18n surface: A — browser-flow form rerender.
		if len(password) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordRequired, nil).Localize(r.Context()))
			return
		}

		if len(password) > 0 && len(passwordConfirmation) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordConfirmationRequired, nil).Localize(r.Context()))
			return
		}

		if password != passwordConfirmation {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordConfirmationMismatch, nil).Localize(r.Context()))
			return
		}

		err = passwordValidator.ValidatePassword(r.Context(), password)
		if err != nil {
			// i18n surface: A — browser-flow form rerender.
			var locErr *i18n.LocalizedError
			if errors.As(err, &locErr) {
				renderError(locErr.Localize(r.Context()))
			} else {
				renderError(err.Error())
			}
			return
		}

		if settings.SMTPEnabled && settings.SelfRegistrationRequiresEmailVerification {
			passwordHash, err := passwordhash.Hash(password)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			verificationCode := stringutil.GenerateSecurityRandomString(32)
			verificationCodeEncrypted, err := encryption.EncryptData(verificationCode)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// The hash is how the activation link finds this row again, since the link
			// carries the code and no email address (#112). The encryption above stays: it
			// is what proves a submitted code matches, where the hash only locates the row.
			verificationCodeHash, err := hashutil.HashString(verificationCode)
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
				VerificationCodeHash:      verificationCodeHash,
			}

			err = database.CreatePreRegistration(r.Context(), nil, preRegistration)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.AuditCreatedPreRegistration, map[string]interface{}{
				"email": preRegistration.Email,
			})

			bind := map[string]interface{}{
				// The code and nothing else: the address used to travel here too, which broke
				// every '+' and '%xx' address under form-urlencoded query parsing (#112). The
				// helper also owns the path the activation handler redirects back to, so the
				// two cannot drift.
				"link": emaillinks.AccountActivateLink(verificationCode),
			}
			// Pre-registration recipient has no stored locale yet; render in
			// the originating request's locale so the activation email matches
			// the language the user just registered in.
			emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, i18n.LocaleTag(r.Context())))
			buf, err := httpHelper.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_register_activate.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			input := &emaildelivery.SendEmailInput{
				To:       email,
				Subject:  i18n.T(emailReq.Context(), "email.register_activate.subject"),
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), input)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			bind = map[string]interface{}{
				"email": email,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		} else {
			passwordHash, err := passwordhash.Hash(password)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			_, err = userCreator.CreateUser(r.Context(), &usercreation.CreateUserInput{
				Email:         email,
				EmailVerified: false,
				PasswordHash:  passwordHash,
			})
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.AuditCreatedUser, map[string]interface{}{
				"email": email,
			})

			if settings.SMTPEnabled {
				bind := map[string]interface{}{
					"link": config.GetAdminConsole().BaseURL + "/account/profile",
				}
				// Recipient is the freshly-created user; no stored Locale yet,
				// so the welcome email uses the locale they registered in.
				emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, i18n.LocaleTag(r.Context())))
				buf, emailErr := httpHelper.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_register_confirmation.html", bind)
				if emailErr != nil {
					httpHelper.InternalServerError(w, r, emailErr)
					return
				}

				input := &emaildelivery.SendEmailInput{
					To:       email,
					Subject:  i18n.T(emailReq.Context(), "email.register_confirmation.subject"),
					HtmlBody: buf.String(),
				}
				emailErr = emailSender.SendEmail(r.Context(), input)
				if emailErr != nil {
					httpHelper.InternalServerError(w, r, emailErr)
					return
				}
			}

			bind := map[string]interface{}{
				"adminConsoleBaseUrl": config.GetAdminConsole().BaseURL,
			}
			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_success.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}
	}
}
