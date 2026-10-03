package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
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
	database accountEmailDatabase,
	emailValidator accountEmailValidator,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
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
	}
}
