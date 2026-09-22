package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
)

// accountEmailDatabase is what the account email endpoints need: the caller's own user row.
type accountEmailDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
}

// HandleAPIAccountEmailPut - PUT /api/v1/account/email
func HandleAPIAccountEmailPut(
	database accountEmailDatabase,
	emailValidator *accountvalidation.EmailValidator,
	auditLogger AuditLogger,
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
		user, err := database.GetUserBySubject(r.Context(), nil, subject)
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
		if err := emailValidator.ValidateEmailChange(r.Context(), email, user.Subject); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Apply updates
		user.Email = email
		user.EmailVerified = false
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}

		if err := database.UpdateUser(r.Context(), nil, user); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

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
