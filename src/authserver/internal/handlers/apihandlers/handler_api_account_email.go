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
	"github.com/leodip/goiabada/core/validators"
)

// HandleAPIAccountEmailPut - PUT /api/v1/account/email
func HandleAPIAccountEmailPut(
	database data.Database,
	emailValidator *validators.EmailValidator,
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

		// Parse request body
		var req api.UpdateAccountEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Load user
		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate email (server-side rules; confirmation is a UI concern)
		email := strings.ToLower(strings.TrimSpace(req.Email))
		if err := emailValidator.ValidateEmailChange(email, user.Subject); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Apply updates
		user.Email = email
		user.EmailVerified = false
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}

		if err := database.UpdateUser(nil, user); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit
		auditLogger.Log(r.Context(), constants.AuditUpdatedOwnEmail, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": subject,
		})

		// Response
		resp := api.UpdateUserResponse{User: *api.ToUserResponse(user)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
