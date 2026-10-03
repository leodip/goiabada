package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// accountEmailDatabase is what the account email endpoints need: the caller's own user row.
type accountEmailDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	SetUserEmail(ctx context.Context, tx *sql.Tx, userId int64, email string) error
}

// accountEmailValidator is the self-service change check: the address rules, and that no other
// account holds the address.
type accountEmailValidator interface {
	ValidateEmailChange(ctx context.Context, email string, subject string) error
}

// HandleAPIAccountEmailPut - PUT /api/v1/account/email
func HandleAPIAccountEmailPut(
	pageRenderer PageRenderer,
	database accountEmailDatabase,
	emailValidator accountEmailValidator,
	emailSender EmailSender,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
	afterResponse AfterResponse,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth and scope are enforced by middleware; extract validated token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		subject := jwtToken.GetStringClaim("sub")
		if strings.TrimSpace(subject) == "" {
			writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
			return
		}

		// Parse request body
		var req api.UpdateAccountEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The change requires the current password, as the password change beside it does (#404).
		// A blank one is refused before the account is read and charges nothing: no password was
		// compared, so charging it would let a caller spend the budget without guessing (#219).
		if strings.TrimSpace(req.CurrentPassword) == "" {
			writeJSONError(w, "Current password is required.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Load user
		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Verify the current password before anything is said about the address, so a caller
		// without it cannot learn whether an address is registered. A wrong one spends the budget
		// PUT /api/v1/account/password and PUT /api/v1/account/otp share, since all three verify
		// the same secret.
		if !passwordhash.Verify(user.PasswordHash, req.CurrentPassword) {
			credentialFailures.RecordCredentialFailure(r)

			writeJSONError(w, "Authentication failed. Check your current password and try again.", "AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}

		// The address the account already has changes nothing. Saving it would clear the
		// verified flag, and with it the account's password recovery, over an idle re-save of
		// the form (#404).
		email := strings.ToLower(strings.TrimSpace(req.Email))
		if email == user.Email {
			writeJSON(w, r, http.StatusOK, api.UpdateUserResponse{User: *apimapping.ToUserResponse(user)})
			return
		}

		// Validate email (server-side rules; confirmation is a UI concern)
		if err := emailValidator.ValidateEmailChange(r.Context(), email, user.Subject); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// A narrow write, not the row loaded above: writing that back would undo a concurrent
		// disable, password change or OTP change (#404).
		if err := database.SetUserEmail(r.Context(), nil, user.Id, email); err != nil {
			writeEmailTakenOrInternalServerError(w, r, err)
			return
		}
		previousEmail := user.Email
		previousEmailVerified := user.EmailVerified
		user.Email = email
		user.EmailVerified = false
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}
		user.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

		// Audit
		auditLogger.Log(r.Context(), audit.AuditUpdatedOwnEmail, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": subject,
		})

		// Response
		resp := api.UpdateUserResponse{User: *apimapping.ToUserResponse(user)}
		writeJSON(w, r, http.StatusOK, resp)

		// Only a verified address is told. Any caller may set an address they do not hold and then
		// change away from it, so an unverified one would let them mail any address on demand, one
		// password-checked request per message. An address is verified only with a code read from
		// its own mailbox, and every change clears the flag, so each notice costs a code read from
		// the address it goes to (#404).
		if previousEmailVerified {
			notifyPreviousAddress(r, pageRenderer, emailSender, afterResponse, previousEmail, user)
		}
	}
}

// notifyPreviousAddress tells the address the account had that it was changed, which is what warns
// an account holder whose password was stolen (#404 decisions 9 and 11). It is sent only to a
// verified address, which the caller decides, and only when SMTP is enabled, and after the response, so the change neither waits for the mail nor fails with it:
// a notice that cannot be rendered or sent is an Error record on the request's id, and writes no
// audit entry of its own.
//
// The notice names neither the new address, which whoever reads the old mailbox has no business
// learning, nor carries a link. It is rendered in the user's stored locale, falling back to
// English, as the reset mail is.
func notifyPreviousAddress(r *http.Request, pageRenderer PageRenderer, emailSender EmailSender,
	afterResponse AfterResponse, previousEmail string, user *models.User) {

	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		slog.ErrorContext(r.Context(), "unable to notify the previous email address", "user_id", user.Id, "error", reqctx.ErrNoSettings)
		return
	}
	if !settings.SMTPEnabled {
		return
	}

	userId := user.Id
	bind := map[string]interface{}{
		"name": user.FullName(),
	}
	locale := user.Locale
	smtpConfig := emaildelivery.SMTPConfigFromSettings(settings)

	afterResponse.Go(r.Context(), func(ctx context.Context) {
		// The request is read for nothing but the renderer's inputs, under the job's context:
		// the request's own is cancelled once the response has gone.
		emailReq := r.WithContext(i18n.WithLocale(ctx, true, locale, "en"))
		buf, err := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_address_changed.html", bind)
		if err != nil {
			slog.ErrorContext(ctx, "unable to render the email address change notice", "user_id", userId, "error", err)
			return
		}

		input := &emaildelivery.SendEmailInput{
			To:       previousEmail,
			Subject:  i18n.T(emailReq.Context(), "email.address_changed.subject"),
			HtmlBody: buf.String(),
		}
		if err := emailSender.SendEmail(ctx, smtpConfig, input); err != nil {
			slog.ErrorContext(ctx, "unable to send the email address change notice", "user_id", userId, "error", err)
		}
	})
}
