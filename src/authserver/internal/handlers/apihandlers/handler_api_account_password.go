package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIAccountPasswordPut - PUT /api/v1/account/password
func HandleAPIAccountPasswordPut(
	database data.Database,
	passwordValidator *validators.PasswordValidator,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Token and scope are enforced by middleware; extract validated token
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

		// Decode request
		var req api.UpdateAccountPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if strings.TrimSpace(req.CurrentPassword) == "" {
			writeJSONError(w, "Current password is required.", "CURRENT_PASSWORD_REQUIRED", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.NewPassword) == "" {
			writeJSONError(w, "New password is required.", "PASSWORD_REQUIRED", http.StatusBadRequest)
			return
		}

		// Load user
		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Verify current password
		if !hashutil.VerifyPasswordHash(user.PasswordHash, req.CurrentPassword) {
			writeJSONError(w, "Authentication failed. Check your current password and try again.", "AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}

		// Validate new password against policy
		if err := passwordValidator.ValidatePassword(r.Context(), req.NewPassword); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Hash and update
		passwordHash, err := hashutil.HashPassword(req.NewPassword)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// The ONE site that preserves a session (#106 decision 4): the user changing their own
		// password should not be logged out of the client they are doing it from. exceptSid
		// comes from the validated token's own sid claim, so it cannot be chosen by the caller.
		//
		// It is empty for a bearer that carries no sid, which after decision 9 means any
		// offline or ROPC access token. That is correct rather than a gap: such a token proves
		// no live session to preserve, so the change revokes everything, which is the
		// conservative direction.
		exceptSid := strings.TrimSpace(jwtToken.GetStringClaim("sid"))

		// Narrow write, not a full-row UpdateUser: the user model was loaded before the
		// password was validated, so writing every column back would undo a concurrent admin
		// disable (decision 14).
		result, err := handlers.RevokeUserAuthStateTx(database, user.Id, exceptSid,
			func(tx *sql.Tx) error {
				return database.SetUserPasswordHash(tx, user.Id, passwordHash)
			})
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Both events, after commit. The pre-existing one is unchanged, per decision 7: every
		// existing event stays exactly as it is, and the revocation gets its own so revocations
		// are queryable as a class rather than spread across four generic event types.
		auditLogger.Log(constants.AuditChangedPassword, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": subject,
		})
		handlers.LogRevokedUserAuthState(auditLogger, user.Id,
			handlers.RevocationReasonPasswordChange, subject, result)

		// Response
		resp := api.UpdateUserResponse{User: *api.ToUserResponse(user)}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}
