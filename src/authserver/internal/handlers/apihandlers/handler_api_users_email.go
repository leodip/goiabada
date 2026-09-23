package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
)

// usersEmailDatabase is what the administrator's user email endpoint needs: the user row.
type usersEmailDatabase interface {
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
}

// usersEmailValidator is the administrator's update check: the address rules, the confirmation,
// and that no other account holds the address.
type usersEmailValidator interface {
	ValidateEmailUpdate(ctx context.Context, input *accountvalidation.ValidateEmailInput) error
}

// HandleAPIUserEmailPut - PUT /api/v1/admin/users/{id}/email
func HandleAPIUserEmailPut(
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		input := &accountvalidation.ValidateEmailInput{
			Email:             strings.ToLower(strings.TrimSpace(req.Email)),
			EmailConfirmation: strings.ToLower(strings.TrimSpace(req.Email)),
			Subject:           user.Subject,
		}

		err = emailValidator.ValidateEmailUpdate(r.Context(), input)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Update user email fields
		user.Email = input.Email
		user.EmailVerified = req.EmailVerified
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = sql.NullTime{Valid: false}

		// Update user in database
		err = database.UpdateUser(r.Context(), nil, user)
		if err != nil {
			writeEmailTakenOrInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := middleware.GetValidatedToken(r)
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.GetStringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.AuditUpdatedUserEmail, map[string]interface{}{
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
