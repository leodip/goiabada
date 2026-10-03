package accounthandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/stringutil"
)

func HandleForgotPasswordGet(
	pageRenderer PageRenderer,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"error": nil,
		}

		err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

	}
}

// forgotPasswordDatabase is what the forgot password page needs: the user it stamps with a reset
// code.
type forgotPasswordDatabase interface {
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*models.User, error)
	TryStoreForgotPasswordCode(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte,
		codeHash string, issuedAt time.Time) (bool, error)
}

// canRecoverPassword reports whether forgot-password may mail a reset link to this account:
// only to an address the account has proven, and only while it is enabled (#404 decisions 1
// and 2). Every other account is answered exactly as an address with no account is.
//
// Only issuance reads verification. Redeeming a link checks the account is enabled and not
// whether its address is verified, so the administrator's setup link, issued to a new user's
// possibly unverified address, keeps working.
func canRecoverPassword(user *models.User) bool {
	return user.Enabled && user.EmailVerified
}

// The outcomes a forgot-password request is recorded with, one per request, in the
// requested_password_reset entry (#404 decision 6). Every well-formed request is answered with the
// same page whichever of these it was, so the entry is the only place the difference is visible.
const (
	// recoveryOutcomeCodeIssued is a code stored for a verified, enabled account. It says
	// the code was stored, not that the mail went out: the entry is written before the send, and
	// a send failure is an Error log line on the same request id.
	recoveryOutcomeCodeIssued = "code_issued"
	// recoveryOutcomeUnknownAddress is an address with no account.
	recoveryOutcomeUnknownAddress = "unknown_address"
	// recoveryOutcomeUnverifiedAddress is an enabled account whose address was never
	// verified, to which decision 1 sends nothing. Named so an administrator can see why.
	recoveryOutcomeUnverifiedAddress = "unverified_address"
	// recoveryOutcomeAccountDisabled is a disabled account, verified or not: disabled is
	// what an administrator did, and verifying the address would not change the answer.
	recoveryOutcomeAccountDisabled = "account_disabled"
	// recoveryOutcomeAccountChanged is the conditional store declining: the account was
	// disabled, unverified or re-addressed between the lookup and the write.
	recoveryOutcomeAccountChanged = "account_changed"
	// recoveryOutcomeInvalidAddress is a submission the format check refused, which is
	// answered with its own error page and looks nothing up.
	recoveryOutcomeInvalidAddress = "invalid_address"
)

// ineligibleRecoveryOutcome names why canRecoverPassword refused an account.
func ineligibleRecoveryOutcome(user *models.User) string {
	if !user.Enabled {
		return recoveryOutcomeAccountDisabled
	}
	return recoveryOutcomeUnverifiedAddress
}

// auditRequestedPasswordReset writes the one requested_password_reset entry a request leaves.
//
// The address is digested rather than recorded, because the table would otherwise collect every
// address typed into an unauthenticated form, attacker-chosen or mistyped; the digest still lets
// attempts on one address be correlated, and checked against a known one. It is of the address
// as the lookup was given it, so it is the same for every spelling the lookup treats as one.
// userId is absent, not zero, when no account matched (#404 decision 6).
func auditRequestedPasswordReset(auditLogger AuditLogger, r *http.Request, email string, userId int64, outcome string) {
	details := map[string]interface{}{
		"ip":          auditedClientIP(r),
		"emailDigest": hashutil.HashString(email),
		"outcome":     outcome,
	}
	if userId != 0 {
		details["userId"] = userId
	}
	auditLogger.Log(r.Context(), audit.AuditRequestedPasswordReset, details)
}

func HandleForgotPasswordPost(
	pageRenderer PageRenderer,
	database forgotPasswordDatabase,
	emailSender EmailSender,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := r.FormValue("email")
		email = strings.ToLower(email)

		if len(email) == 0 || strings.Count(email, "@") != 1 {
			auditRequestedPasswordReset(auditLogger, r, email, 0, recoveryOutcomeInvalidAddress)

			// i18n surface: A — browser-flow form rerender.
			bind := map[string]interface{}{
				"error": i18n.NewLocalizedError(i18n.ErrCodeEmailInvalidFormat, nil).Localize(r.Context()),
			}

			err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
			return
		}

		user, err := database.GetUserByEmail(r.Context(), nil, email)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		switch {
		case user == nil:
			auditRequestedPasswordReset(auditLogger, r, email, 0, recoveryOutcomeUnknownAddress)
		case !canRecoverPassword(user):
			auditRequestedPasswordReset(auditLogger, r, email, user.Id, ineligibleRecoveryOutcome(user))
		default:

			verificationCode := stringutil.GenerateSecurityRandomString(32)
			verificationCodeEncrypted, resetEmailErr := dataCipher.Encrypt(verificationCode)
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}

			// The hash is how the reset link finds this row again, since the link carries
			// the code and no email address (#112). The encryption above stays: it is what
			// proves a submitted code matches, where the hash only locates the row.
			verificationCodeHash := hashutil.HashString(verificationCode)

			// Narrow and conditional rather than writing back the row loaded above, which
			// carried enabled and would re-enable an account an administrator disabled
			// meanwhile. The store takes effect only while the account is still enabled and
			// its address still verified and still the one looked up; when it declines, the
			// request is answered as one for an address with no account and nothing is
			// mailed (#404 decision 2).
			stored, resetEmailErr := database.TryStoreForgotPasswordCode(r.Context(), nil, user.Id, user.Email,
				verificationCodeEncrypted, verificationCodeHash, time.Now().UTC())
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}
			if !stored {
				auditRequestedPasswordReset(auditLogger, r, email, user.Id, recoveryOutcomeAccountChanged)
				renderForgotPasswordLinkSent(pageRenderer, w, r)
				return
			}
			auditRequestedPasswordReset(auditLogger, r, email, user.Id, recoveryOutcomeCodeIssued)

			bind := map[string]interface{}{
				"name": user.FullName(),
				"link": emaillinks.ResetPasswordLink(baseURL, verificationCode),
			}
			emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, user.Locale, "en"))
			buf, resetEmailErr := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_forgot_password.html", bind)
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}

			input := &emaildelivery.SendEmailInput{
				To:       user.Email,
				Subject:  i18n.T(emailReq.Context(), "email.forgot_password.subject"),
				HtmlBody: buf.String(),
			}
			settings, ok := reqctx.SettingsFrom(r.Context())
			if !ok {
				pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
				return
			}
			resetEmailErr = emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input)
			if resetEmailErr != nil {
				pageRenderer.InternalServerError(w, r, resetEmailErr)
				return
			}
		}

		renderForgotPasswordLinkSent(pageRenderer, w, r)
	}
}

// renderForgotPasswordLinkSent is the one answer to a well-formed request, whatever became of it,
// so the page itself does not tell an address with no account from one that was mailed.
func renderForgotPasswordLinkSent(pageRenderer PageRenderer, w http.ResponseWriter, r *http.Request) {
	bind := map[string]interface{}{
		"linkSent": true,
	}

	if err := pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/forgot_password.html", bind); err != nil {
		pageRenderer.InternalServerError(w, r, err)
	}
}
