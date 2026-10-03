package apihandlers

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// accountEmailVerificationDatabase is what the account email verification endpoints need: the
// caller's own user row.
type accountEmailVerificationDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	TryStoreEmailVerificationCode(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte,
		issuedAt time.Time, issuedNotAfter time.Time) (bool, error)
	TryVerifyUserEmail(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte) (bool, error)
}

// emailVerificationCodeLifetime is how long an email verification code verifies, and also the
// resend cooldown: an account may have a code sent once per lifetime, so it holds at most one
// live code at a time. The cooldown is what bounds the mail an account can have sent with the
// rate limiter off, its default, and the account chooses the address that mail goes to, so the
// two are one value rather than two that could drift apart (#404).
const emailVerificationCodeLifetime = 5 * time.Minute

// HandleAPIAccountEmailVerificationSendPost - POST /api/v1/account/email/verification/send
func HandleAPIAccountEmailVerificationSendPost(
	pageRenderer PageRenderer,
	database accountEmailVerificationDatabase,
	emailSender EmailSender,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
	adminConsoleBaseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth and scope are enforced by middleware; extract validated token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		subject := jwtToken.StringClaim("sub")
		if strings.TrimSpace(subject) == "" {
			writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SMTPEnabled {
			writeJSONError(w, "SMTP is not enabled", "SMTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "Failed to get user by subject in email verification send (first call)"), "subject", subject)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if writeSendNotNeeded(w, r, user) {
			return
		}

		// Generate code and store encrypted
		verificationCode := generateEmailVerificationCode()
		encrypted, err := dataCipher.Encrypt(verificationCode)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "Failed to encrypt verification code"))
			return
		}

		// The check above answers the common case; this write is the one that decides. It
		// stores the code only while the account still holds this address, unverified, with no
		// code issued inside the cooldown, so of concurrent sends exactly one claims the code
		// and mails it. The check alone let all of them through, and the account chooses the
		// address the mail goes to (#404).
		issuedAt := time.Now().UTC()
		claimed, err := database.TryStoreEmailVerificationCode(r.Context(), nil, user.Id, user.Email, encrypted,
			issuedAt, issuedAt.Add(-emailVerificationCodeLifetime))
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "Failed to store the verification code"), "user_id", user.Id)
			return
		}
		if !claimed {
			// Another request got there first: a send that claimed the code, a verification, or an
			// email change. Read the row again and answer what it now says.
			current, rereadErr := database.GetUserBySubject(r.Context(), nil, subject)
			if rereadErr != nil {
				writeInternalServerError(w, r, errs.Wrap(rereadErr, "Failed to get user by subject in email verification send (after a lost claim)"), "subject", subject)
				return
			}
			if current != nil && writeSendNotNeeded(w, r, current) {
				return
			}
			writeJSONError(w, "The account was changed by another request while the code was being sent. Nothing was sent: try again.", "CONCURRENT_UPDATE", http.StatusConflict)
			return
		}
		user.EmailVerificationCodeEncrypted = encrypted
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: issuedAt, Valid: true}

		// Render email content
		bind := map[string]interface{}{
			"name":             user.FullName(),
			"link":             adminConsoleBaseURL + "/account/email-verification",
			"verificationCode": verificationCode,
		}
		emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, user.Locale, "en"))
		buf, err := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_verification.html", bind)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "Failed to render email template"), "user_id", user.Id)
			return
		}

		input := &emaildelivery.SendEmailInput{
			To:       user.Email,
			Subject:  i18n.T(emailReq.Context(), "email.verification.subject", map[string]any{"code": verificationCode}),
			HtmlBody: buf.String(),
		}
		if err := emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "Failed to send verification email"), "user_id", user.Id, "email", user.Email)
			return
		}

		// Audit
		auditLogger.Log(r.Context(), audit.AuditSentEmailVerificationMessage, map[string]interface{}{
			"userId":           user.Id,
			"emailDestination": user.Email,
			"loggedInUser":     subject,
		})

		// Response
		resp := api.AccountEmailVerificationSendResponse{
			EmailVerificationSent: true,
			EmailDestination:      user.Email,
		}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// writeSendNotNeeded answers a send the account does not need, and reports whether it did: an
// address already verified, or a code issued inside the cooldown.
//
// The resend cooldown is the account's, not the address's: it reads when a code was last issued
// whether or not that code is still pending. An email change and a verification clear the code
// and keep this, so changing away from an address and back to it does not reopen a send to it
// (#404).
func writeSendNotNeeded(w http.ResponseWriter, r *http.Request, user *models.User) bool {
	if user.EmailVerified {
		writeJSON(w, r, http.StatusOK, api.AccountEmailVerificationSendResponse{EmailVerified: true})
		return true
	}
	if user.EmailVerificationCodeIssuedAt.Valid {
		// Rounded up, so the last partial second still answers the wait rather than reaching a
		// write whose cutoff refuses it.
		remaining := int(math.Ceil(user.EmailVerificationCodeIssuedAt.Time.Add(emailVerificationCodeLifetime).Sub(time.Now().UTC()).Seconds()))
		if remaining > 0 {
			writeJSON(w, r, http.StatusOK, api.AccountEmailVerificationSendResponse{TooManyRequests: true, WaitInSeconds: remaining})
			return true
		}
	}
	return false
}

// HandleAPIAccountEmailVerificationPost - POST /api/v1/account/email/verification
func HandleAPIAccountEmailVerificationPost(
	database accountEmailVerificationDatabase,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth and scope are enforced by middleware; extract validated token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		subject := jwtToken.StringClaim("sub")
		if strings.TrimSpace(subject) == "" {
			writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !settings.SMTPEnabled {
			writeJSONError(w, "SMTP is not enabled", "SMTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		var req api.VerifyAccountEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		code := strings.TrimSpace(req.VerificationCode)

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if user.EmailVerified {
			// Already verified; return current state
			resp := api.UpdateUserResponse{User: *apimapping.ToUserResponse(user)}
			writeJSON(w, r, http.StatusOK, resp)
			return
		}

		storedCode, err := dataCipher.Decrypt(user.EmailVerificationCodeEncrypted)
		if err != nil {
			// Treat as mismatch
			storedCode = ""
		}

		// Constant-time, and unlike its siblings this comparison is reached on every guess:
		// the reset-password code, client secrets and HOTP all compare with
		// subtle.ConstantTimeCompare already. Uppercasing the submission keeps the
		// case-insensitive input the single-case alphabet relies on, and drops only exotic
		// Unicode foldings that no generated code can contain.
		//
		// The emptiness check is not redundant. Decryption failure above leaves storedCode
		// empty, and two empty strings compare equal under both this and the EqualFold that
		// preceded it, so without it the request is refused only by the IssuedAt check
		// behind the comparison (#219).
		codeMatches := len(storedCode) > 0 && len(code) > 0 &&
			subtle.ConstantTimeCompare([]byte(storedCode), []byte(strings.ToUpper(code))) == 1

		if !codeMatches || !user.EmailVerificationCodeIssuedAt.Valid ||
			user.EmailVerificationCodeIssuedAt.Time.Add(emailVerificationCodeLifetime).Before(time.Now().UTC()) {

			// The only branch that is a guess against the code. A missing token, a blank
			// subject, disabled SMTP and an unknown user are refused before anything is
			// compared, so charging them would let a caller spend a budget without ever
			// attempting the credential.
			credentialFailures.RecordCredentialFailure(r)

			auditLogger.Log(r.Context(), audit.AuditFailedEmailVerificationCode, map[string]interface{}{
				"userId":       user.Id,
				"loggedInUser": subject,
			})

			writeJSONError(w, "Invalid or expired verification code", "INVALID_OR_EXPIRED_VERIFICATION_CODE", http.StatusBadRequest)
			return
		}

		// The code is spent; its issued-at stays for the resend cooldown, which would otherwise
		// let a send to an address the caller controls be followed at once by one to an address
		// they do not, once they changed to it. A narrow, conditional write: it verifies only
		// while the account holds the address it read with the ciphertext it compared still
		// pending, and writes back nothing else of the row it loaded, which could re-enable an
		// account an administrator disabled meanwhile, or put back an address a concurrent change
		// replaced (#404).
		verified, err := database.TryVerifyUserEmail(r.Context(), nil, user.Id, user.Email, user.EmailVerificationCodeEncrypted)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if !verified {
			// The code was right when compared and is gone now. Either a twin submission of it
			// verified the address first, which this request answers as that one did, or a new
			// send or an email change replaced it, which leaves it invalid. Neither was a guess,
			// so neither spends the failure budget or writes a failed-code entry.
			current, err := database.GetUserBySubject(r.Context(), nil, subject)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}
			if current != nil && current.EmailVerified && current.Email == user.Email {
				writeJSON(w, r, http.StatusOK, api.UpdateUserResponse{User: *apimapping.ToUserResponse(current)})
				return
			}
			writeJSONError(w, "Invalid or expired verification code", "INVALID_OR_EXPIRED_VERIFICATION_CODE", http.StatusBadRequest)
			return
		}
		user.EmailVerified = true
		user.EmailVerificationCodeEncrypted = nil
		user.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

		auditLogger.Log(r.Context(), audit.AuditVerifiedEmail, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": subject,
		})

		resp := api.UpdateUserResponse{User: *apimapping.ToUserResponse(user)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
