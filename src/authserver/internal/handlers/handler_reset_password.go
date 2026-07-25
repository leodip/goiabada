package handlers

import (
	"crypto/subtle"
	"database/sql"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
)

// forgotPasswordCodeLifetime bounds how long a password reset code stays usable
// after it is issued by HandleForgotPasswordPost.
const forgotPasswordCodeLifetime = 5 * time.Minute

// isForgotPasswordCodeExpired reports whether the reset code issued to this user
// is past its lifetime.
//
// Both HandleResetPasswordGet and HandleResetPasswordPost must consult this. The
// GET only renders a warning, so enforcing the lifetime there alone left the POST
// accepting a code of any age, which made a leaked reset link valid forever.
//
// A user with no code issued has a zero ForgotPasswordCodeIssuedAt and is
// therefore treated as expired, which fails closed.
func isForgotPasswordCodeExpired(user *models.User) bool {
	return user.ForgotPasswordCodeIssuedAt.Time.Add(forgotPasswordCodeLifetime).Before(time.Now().UTC())
}

// forgotPasswordCodeMatches compares a supplied reset code against the stored one
// in constant time, the same way client secrets are compared in
// validators.ValidateTokenRequest. A plain string comparison stops at the first
// differing byte, which in principle leaks how much of a guessed code was right.
//
// Both HandleResetPasswordGet and HandleResetPasswordPost must use this, so that
// neither reverts to a short-circuiting comparison on its own.
//
// This is not constant time with respect to length: inputs of differing lengths
// are rejected immediately. Reset codes are fixed length, so that difference
// carries nothing useful.
func forgotPasswordCodeMatches(storedCode string, suppliedCode string) bool {
	return subtle.ConstantTimeCompare([]byte(storedCode), []byte(suppliedCode)) == 1
}

// renderResetPasswordCodeInvalid renders the reset form in its "invalid or
// expired" state.
//
// Every condition attributable to the link goes through here: a missing code or
// email, an unknown email address, a user with no code issued, a wrong code, and
// an expired code. Because they all produce the same response, the endpoint
// cannot be used to work out which of them happened, and in particular cannot be
// used to discover whether an email address has an account.
//
// httpStatus is applied only when non-zero. The GET passes zero so that simply
// viewing a dead link keeps rendering with the 200 it has always used: the page
// itself was served successfully, and reset links are fetched by mail scanners
// and link previewers that treat a 4xx as a broken link. The POST passes 400,
// because there a submission was genuinely refused.
//
// Genuine server faults must NOT come here. A stored code that will not decrypt,
// or a database failure, stays an InternalServerError so it keeps its stack trace
// and keeps alerting.
func renderResetPasswordCodeInvalid(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, httpStatus int) {
	bind := map[string]interface{}{
		"codeInvalidOrExpired": true,
		"csrfField":            csrf.TemplateField(r),
	}
	if httpStatus != 0 {
		bind["_httpStatus"] = httpStatus
	}

	if err := httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/reset_password.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// auditFailedResetPasswordCode records a refused reset submission.
//
// The response is identical for every reason (see renderResetPasswordCodeInvalid),
// so this audit entry is the only place the actual cause is visible. That is
// deliberate: the detail is available to an administrator, who needs it to spot
// probing, and withheld from the caller, who would otherwise learn whether an
// address has an account.
//
// The email comes from the query string, so it is attacker-controlled and
// unbounded; it is truncated before being stored.
func auditFailedResetPasswordCode(auditLogger AuditLogger, email string, reason string) {
	const maxAuditedEmailLength = 100
	if len(email) > maxAuditedEmailLength {
		email = email[:maxAuditedEmailLength]
	}

	auditLogger.Log(constants.AuditFailedResetPasswordCode, map[string]interface{}{
		"email":  email,
		"reason": reason,
	})
}

func HandleResetPasswordGet(
	httpHelper HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		code := r.URL.Query().Get("code")
		email := r.URL.Query().Get("email")
		if len(code) == 0 || len(email) == 0 {
			renderResetPasswordCodeInvalid(httpHelper, w, r, 0)
			return
		}

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// An unknown address, and a known address with no pending reset code, are
		// answered exactly as a wrong code is.
		if user == nil || len(user.ForgotPasswordCodeEncrypted) == 0 {
			renderResetPasswordCodeInvalid(httpHelper, w, r, 0)
			return
		}

		forgotPasswordCode, err := encryption.DecryptData(user.ForgotPasswordCodeEncrypted)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.Wrap(err, "unable to decrypt forgot password code"))
			return
		}

		if !forgotPasswordCodeMatches(forgotPasswordCode, code) || isForgotPasswordCodeExpired(user) {
			renderResetPasswordCodeInvalid(httpHelper, w, r, 0)
			return
		}

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
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
	auditLogger AuditLogger,
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

		// i18n surface: A — browser-flow form rerender.
		if len(password) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordRequired, nil).Localize(r.Context()))
			return
		}

		if password != passwordConfirmation {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeHandlerPasswordConfirmationMismatch, nil).Localize(r.Context()))
			return
		}

		err := passwordValidator.ValidatePassword(r.Context(), password)
		if err != nil {
			// i18n surface: A — browser-flow form rerender.
			if locErr, ok := err.(*i18n.LocalizedError); ok {
				renderError(locErr.Localize(r.Context()))
			} else {
				renderError(err.Error())
			}
			return
		}

		// Refuse with an identical response but an audited cause. The branches are
		// kept separate only so the audit entry can name the reason.
		reject := func(reason string) {
			auditFailedResetPasswordCode(auditLogger, r.URL.Query().Get("email"), reason)
			renderResetPasswordCodeInvalid(httpHelper, w, r, http.StatusBadRequest)
		}

		code := r.URL.Query().Get("code")
		email := r.URL.Query().Get("email")
		if len(code) == 0 || len(email) == 0 {
			reject("missing_code_or_email")
			return
		}

		user, err := database.GetUserByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			reject("unknown_email")
			return
		}

		if len(user.ForgotPasswordCodeEncrypted) == 0 {
			reject("no_code_issued")
			return
		}

		forgotPasswordCode, err := encryption.DecryptData(user.ForgotPasswordCodeEncrypted)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to decrypt forgot password code")))
			return
		}

		if !forgotPasswordCodeMatches(forgotPasswordCode, code) {
			reject("code_mismatch")
			return
		}

		// The lifetime is enforced here, not only in the GET handler: that one just
		// renders a warning, so without this check a reset link kept working
		// indefinitely once it leaked.
		if isForgotPasswordCodeExpired(user) {
			reject("code_expired")
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
