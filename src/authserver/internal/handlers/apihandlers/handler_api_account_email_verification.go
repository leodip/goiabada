package apihandlers

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/stringutil"
)

// HandleAPIAccountEmailVerificationSendPost - POST /api/v1/account/email/verification/send
func HandleAPIAccountEmailVerificationSendPost(
	httpHelper handlers.HttpHelper,
	database data.Database,
	emailSender handlers.EmailSender,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth and scope are enforced by middleware; extract validated token
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		subject := jwtToken.GetStringClaim("sub")
		if strings.TrimSpace(subject) == "" {
			writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		if !settings.SMTPEnabled {
			writeJSONError(w, "SMTP is not enabled", "SMTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			slog.Error("Failed to get user by subject in email verification send (first call)", "error", err, "subject", subject)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// If already verified, inform client
		if user.EmailVerified {
			resp := api.AccountEmailVerificationSendResponse{EmailVerified: true}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Enforce resend cooldown
		if len(user.EmailVerificationCodeEncrypted) > 0 && user.EmailVerificationCodeIssuedAt.Valid {
			const waitTime = 60 * time.Second
			remaining := int(user.EmailVerificationCodeIssuedAt.Time.Add(waitTime).Sub(time.Now().UTC()).Seconds())
			if remaining > 0 {
				resp := api.AccountEmailVerificationSendResponse{TooManyRequests: true, WaitInSeconds: remaining}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
		}

		// Generate code and store encrypted
		verificationCode := strings.ToUpper(stringutil.GenerateRandomLetterString(3)) + stringutil.GenerateRandomNumberString(3)
		encrypted, err := encryption.EncryptText(verificationCode, settings.AESEncryptionKey)
		if err != nil {
			slog.Error("Failed to encrypt verification code", "error", err)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		user.EmailVerificationCodeEncrypted = encrypted
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		if err := database.UpdateUser(nil, user); err != nil {
			slog.Error("Failed to update user with verification code", "error", err, "userId", user.Id)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Render email content
		bind := map[string]interface{}{
			"name":             user.GetFullName(),
			"link":             config.GetAdminConsole().BaseURL + "/account/email-verification",
			"verificationCode": verificationCode,
		}
		buf, err := httpHelper.RenderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_verification.html", bind)
		if err != nil {
			slog.Error("Failed to render email template", "error", err, "userId", user.Id)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		input := &communication.SendEmailInput{
			To:       user.Email,
			Subject:  "Email verification - code " + verificationCode,
			HtmlBody: buf.String(),
		}
		if err := emailSender.SendEmail(r.Context(), input); err != nil {
			slog.Error("Failed to send verification email", "error", err, "userId", user.Id, "email", user.Email)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Audit
		auditLogger.Log(constants.AuditSentEmailVerificationMessage, map[string]interface{}{
			"userId":           user.Id,
			"emailDestination": user.Email,
			"loggedInUser":     subject,
		})

		// Response
		resp := api.AccountEmailVerificationSendResponse{
			EmailVerificationSent: true,
			EmailDestination:      user.Email,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// HandleAPIAccountEmailVerificationPost - POST /api/v1/account/email/verification
func HandleAPIAccountEmailVerificationPost(
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Auth and scope are enforced by middleware; extract validated token
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		subject := jwtToken.GetStringClaim("sub")
		if strings.TrimSpace(subject) == "" {
			writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
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

		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		if user.EmailVerified {
			// Already verified; return current state
			resp := api.UpdateUserResponse{User: *api.ToUserResponse(user)}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		storedCode, err := encryption.DecryptText(user.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			// Treat as mismatch
			storedCode = ""
		}

		if !strings.EqualFold(storedCode, code) || !user.EmailVerificationCodeIssuedAt.Valid ||
			user.EmailVerificationCodeIssuedAt.Time.Add(5*time.Minute).Before(time.Now().UTC()) {

			auditLogger.Log(constants.AuditFailedEmailVerificationCode, map[string]interface{}{
				"userId":       user.Id,
				"loggedInUser": subject,
			})

			writeJSONError(w, "Invalid or expired verification code", "INVALID_OR_EXPIRED_VERIFICATION_CODE", http.StatusBadRequest)
			return
		}

		user.EmailVerified = true
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}
		if err := database.UpdateUser(nil, user); err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		auditLogger.Log(constants.AuditVerifiedEmail, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": subject,
		})

		resp := api.UpdateUserResponse{User: *api.ToUserResponse(user)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
