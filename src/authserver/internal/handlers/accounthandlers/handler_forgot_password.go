package accounthandlers

import (
	"context"
	"database/sql"
	"log/slog"
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
//
// It takes the context rather than the request because a well-formed request's entry is written
// by the job after its response, under the job's context, which keeps the request's id; the
// client IP is read off the request before the handler returns.
func auditRequestedPasswordReset(ctx context.Context, auditLogger AuditLogger, clientIP string, email string,
	userId int64, outcome string) {
	details := map[string]interface{}{
		"ip":          clientIP,
		"emailDigest": hashutil.HashString(email),
		"outcome":     outcome,
	}
	if userId != 0 {
		details["userId"] = userId
	}
	auditLogger.Log(ctx, audit.AuditRequestedPasswordReset, details)
}

// HandleForgotPasswordPost answers every well-formed request after the format check and the
// lookup alone, with the one "link sent" page, and hands everything else to a job that runs after
// the response: the conditional code store, the audit entry, the render and the send. A live
// account therefore costs the response nothing an address with no account does not, and a mail
// that fails to send is an Error record on the request's id rather than a 500 only a live account
// could get (#404 decisions 7 and 8). A malformed address is answered, and audited, at once, since
// its error page is visibly different anyway.
func HandleForgotPasswordPost(
	pageRenderer PageRenderer,
	database forgotPasswordDatabase,
	emailSender EmailSender,
	auditLogger AuditLogger,
	afterResponse AfterResponse,
	dataCipher *encryption.DataCipher,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := r.FormValue("email")
		email = strings.ToLower(email)
		clientIP := auditedClientIP(r)

		if len(email) == 0 || strings.Count(email, "@") != 1 {
			auditRequestedPasswordReset(r.Context(), auditLogger, clientIP, email, 0, recoveryOutcomeInvalidAddress)

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

		renderForgotPasswordLinkSent(pageRenderer, w, r)

		afterResponse.Go(r.Context(), func(ctx context.Context) {
			finishForgotPassword(ctx, r, database, emailSender, auditLogger, pageRenderer, dataCipher, baseURL,
				clientIP, email, user)
		})
	}
}

// finishForgotPassword is the work after a well-formed request's response: it decides what
// becomes of the request, records that, and for a verified, enabled account stores a code and
// mails the link. ctx is the job's, detached from the request's cancellation and carrying its id,
// so every failure here is an Error record on that id: the requester has already been answered,
// and is told nothing different (#404 decision 8).
//
// r is the request the job was started from, read for nothing but the renderer's inputs. Its
// context is replaced by ctx before anything reads it, since the request's own is cancelled once
// the response has gone.
func finishForgotPassword(
	ctx context.Context,
	r *http.Request,
	database forgotPasswordDatabase,
	emailSender EmailSender,
	auditLogger AuditLogger,
	pageRenderer PageRenderer,
	dataCipher *encryption.DataCipher,
	baseURL string,
	clientIP string,
	email string,
	user *models.User,
) {
	switch {
	case user == nil:
		auditRequestedPasswordReset(ctx, auditLogger, clientIP, email, 0, recoveryOutcomeUnknownAddress)
		return
	case !canRecoverPassword(user):
		auditRequestedPasswordReset(ctx, auditLogger, clientIP, email, user.Id, ineligibleRecoveryOutcome(user))
		return
	}

	verificationCode := stringutil.GenerateSecurityRandomString(32)
	verificationCodeEncrypted, err := dataCipher.Encrypt(verificationCode)
	if err != nil {
		slog.ErrorContext(ctx, "unable to encrypt the password reset code", "user_id", user.Id, "error", err)
		return
	}

	// The hash is how the reset link finds this row again, since the link carries the code and no
	// email address (#112). The encryption above stays: it is what proves a submitted code
	// matches, where the hash only locates the row.
	verificationCodeHash := hashutil.HashString(verificationCode)

	// Narrow and conditional rather than writing back the row loaded by the lookup, which carried
	// enabled and would re-enable an account an administrator disabled meanwhile. The store takes
	// effect only while the account is still enabled and its address still verified and still the
	// one looked up; when it declines, nothing is mailed (#404 decision 2).
	stored, err := database.TryStoreForgotPasswordCode(ctx, nil, user.Id, user.Email,
		verificationCodeEncrypted, verificationCodeHash, time.Now().UTC())
	if err != nil {
		slog.ErrorContext(ctx, "unable to store the password reset code", "user_id", user.Id, "error", err)
		return
	}
	if !stored {
		auditRequestedPasswordReset(ctx, auditLogger, clientIP, email, user.Id, recoveryOutcomeAccountChanged)
		return
	}
	auditRequestedPasswordReset(ctx, auditLogger, clientIP, email, user.Id, recoveryOutcomeCodeIssued)

	bind := map[string]interface{}{
		"name": user.FullName(),
		"link": emaillinks.ResetPasswordLink(baseURL, verificationCode),
	}
	emailReq := r.WithContext(i18n.WithLocale(ctx, true, user.Locale, "en"))
	buf, err := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_forgot_password.html", bind)
	if err != nil {
		slog.ErrorContext(ctx, "unable to render the password reset email", "user_id", user.Id, "error", err)
		return
	}

	settings, ok := reqctx.SettingsFrom(ctx)
	if !ok {
		slog.ErrorContext(ctx, "unable to send the password reset email", "user_id", user.Id, "error", reqctx.ErrNoSettings)
		return
	}
	input := &emaildelivery.SendEmailInput{
		To:       user.Email,
		Subject:  i18n.T(emailReq.Context(), "email.forgot_password.subject"),
		HtmlBody: buf.String(),
	}
	if err := emailSender.SendEmail(ctx, emaildelivery.SMTPConfigFromSettings(settings), input); err != nil {
		slog.ErrorContext(ctx, "unable to send the password reset email", "user_id", user.Id, "error", err)
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
