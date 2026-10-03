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
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/securerandom"
)

// refuseSelfRegistrationDisabled answers a self-registration page, or an activation link, while
// the setting is off: one Warn record and the not-found page.
//
// 404 is RFC 9110 section 15.5.5's status for a resource the server "is not willing to disclose
// that one exists", which is what a feature switched off is. It used to be the 500 page with an
// error-level stack, which alerted an operator for every visitor following an old link to a page
// the operator had turned off on purpose (#425 decision 5).
func refuseSelfRegistrationDisabled(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request) {
	slog.WarnContext(r.Context(), "self-registration request refused because self-registration is disabled")
	pageRenderer.NotFound(w, r)
}

// registrationCeremonyId is the sign-in the visitor came to this page from, when the password page's
// "Register" link said so: the id that link carried, if it has the shape of one. The page puts it back
// into its own "Sign in" link, so a visitor who registers nothing and goes back lands on the same
// sign-in's password form, where without it the link would load a step that names no ceremony and get
// the "no longer active" page (#246 decision 22).
//
// It is only ever echoed into a link, and never checked against a stored ceremony here, so a value
// that is not an id is dropped and not repeated into the page, whatever the visitor put in the query:
// a length and an alphabet that need no escaping and leave no room to smuggle a URL through. Empty
// means the page was reached from anywhere else, an emailed link or a bookmark, and its "Sign in" link
// stays bare.
func registrationCeremonyId(r *http.Request) string {
	id := r.URL.Query().Get(ceremony.QueryParameter)
	if !ceremony.IsWellFormedId(id) {
		return ""
	}
	return id
}

func HandleAccountRegisterGet(
	pageRenderer PageRenderer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(pageRenderer, w, r)
			return
		}

		bind := map[string]interface{}{
			"ceremonyId": registrationCeremonyId(r),
		}

		err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
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
	pageRenderer PageRenderer,
	database accountRegisterDatabase,
	userCreator UserCreator,
	emailValidator EmailValidator,
	passwordValidator PasswordValidator,
	emailSender EmailSender,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SelfRegistrationEnabled {
			refuseSelfRegistrationDisabled(pageRenderer, w, r)
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
			// The form posts to action="", so the URL the visitor arrived at, ceremony parameter
			// included, is the one this request has, and the re-render carries the id on.
			bind := map[string]interface{}{
				"email":      email,
				"error":      message,
				"ceremonyId": registrationCeremonyId(r),
			}

			err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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
			var errorDetail *oauth.ErrorDetail
			switch {
			case errors.As(err, &localizedErr):
				renderError(localizedErr.Localize(r.Context()))
			case errors.As(err, &errorDetail):
				renderError(errorDetail.Description())
			default:
				pageRenderer.InternalServerError(w, r, err)
			}
			return
		}

		alreadyRegisteredMessage := i18n.NewLocalizedError(i18n.ErrCodeEmailAlreadyRegistered, nil).Localize(r.Context())

		user, err := database.GetUserByEmail(r.Context(), nil, email)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if user != nil {
			renderError(alreadyRegisteredMessage)
			return
		}

		preRegistration, err := database.GetPreRegistrationByEmail(r.Context(), nil, email)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
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

		err = passwordValidator.ValidatePassword(settings.PasswordPolicy, password)
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
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			verificationCode := securerandom.String(32)
			verificationCodeEncrypted, err := dataCipher.Encrypt(verificationCode)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			// The hash is how the activation link finds this row again, since the link
			// carries the code and no email address (#112). The encryption above stays: it
			// is what proves a submitted code matches, where the hash only locates the row.
			verificationCodeHash := hashutil.HashString(verificationCode)

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
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.EventCreatedPreRegistration, map[string]interface{}{
				"email": preRegistration.Email,
			})

			bind := map[string]interface{}{
				// The code and nothing else: the address used to travel here too, which broke
				// every '+' and '%xx' address under form-urlencoded query parsing (#112). The
				// helper also owns the path the activation handler redirects back to, so the
				// two cannot drift.
				"link": emaillinks.AccountActivateLink(baseURL, verificationCode),
			}
			// Pre-registration recipient has no stored locale yet; render in
			// the originating request's locale so the activation email matches
			// the language the user just registered in.
			emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, i18n.LocaleTag(r.Context())))
			buf, err := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_register_activate.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			input := &emaildelivery.SendEmailInput{
				To:       email,
				Subject:  i18n.T(emailReq.Context(), "email.register_activate.subject"),
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			bind = map[string]interface{}{
				"email": email,
			}

			err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
		} else {
			passwordHash, err := passwordhash.Hash(password)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			_, err = userCreator.CreateUser(r.Context(), &usercreation.Input{
				Email:         email,
				EmailVerified: false,
				PasswordHash:  passwordHash,
			})
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(r.Context(), audit.EventCreatedUser, map[string]interface{}{
				"email": email,
			})

			if settings.SMTPEnabled {
				bind := map[string]interface{}{
					"link": adminConsoleBaseURL + "/account/profile",
				}
				// Recipient is the freshly-created user; no stored Locale yet,
				// so the welcome email uses the locale they registered in.
				emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, i18n.LocaleTag(r.Context())))
				buf, emailErr := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_register_confirmation.html", bind)
				if emailErr != nil {
					pageRenderer.InternalServerError(w, r, emailErr)
					return
				}

				input := &emaildelivery.SendEmailInput{
					To:       email,
					Subject:  i18n.T(emailReq.Context(), "email.register_confirmation.subject"),
					HtmlBody: buf.String(),
				}
				emailErr = emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input)
				if emailErr != nil {
					pageRenderer.InternalServerError(w, r, emailErr)
					return
				}
			}

			bind := map[string]interface{}{
				"adminConsoleBaseUrl": adminConsoleBaseURL,
			}
			err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_success.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
		}
	}
}
