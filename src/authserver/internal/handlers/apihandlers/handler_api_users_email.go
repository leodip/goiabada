package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// usersEmailDatabase is what the administrator's user email endpoint needs: the user row, and
// the narrow write of its address.
// It embeds what the administrative policy reads to judge whether the user is an administrator.
type usersEmailDatabase interface {
	userTargetPolicyDatabase
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	SetUserEmail(ctx context.Context, tx *sql.Tx, user *record.User) error
}

// usersEmailValidator is the administrator's update check: the address rules, and that no other
// account holds the address.
type usersEmailValidator interface {
	ValidateEmailChange(ctx context.Context, email string, subject string) error
}

// HandleUserEmailPut - PUT /api/v1/admin/users/{id}/email
func HandleUserEmailPut(
	database usersEmailDatabase,
	emailValidator usersEmailValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Parse user ID from URL
		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Parse request body
		var req api.UpdateUserEmailRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate email data
		email := strings.ToLower(strings.TrimSpace(req.Email))

		err = emailValidator.ValidateEmailChange(r.Context(), email, user.Subject)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		// The address group alone, never the row as read: writing that back would undo a disable, a
		// password change or an OTP change made while this request was in flight (#471). The write
		// also clears the pending verification code and any reset code, which belong to the previous
		// address.
		user.Email = email
		user.EmailVerified = req.EmailVerified
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}
		user.ForgotPasswordCodeEncrypted = nil
		user.ForgotPasswordCodeIssuedAt = sql.NullTime{Valid: false}
		user.ForgotPasswordCodeHash = ""

		err = database.SetUserEmail(r.Context(), nil, user)
		if err != nil {
			writeEmailTakenOrInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.EventUpdatedUserEmail, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})

		// Create response
		response := api.UpdateUserResponse{
			User: *apimapping.ToUserResponse(user),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}
