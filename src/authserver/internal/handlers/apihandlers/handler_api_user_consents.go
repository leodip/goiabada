package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
)

// userConsentsDatabase is what the administrator's user consent endpoints need: one user's
// consents and the clients they name.
type userConsentsDatabase interface {
	DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentId int64) error
	GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserConsent, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserConsentById(ctx context.Context, tx *sql.Tx, userConsentId int64) (*models.UserConsent, error)
	UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []models.UserConsent) error
}

func HandleAPIUserConsentsGet(
	database userConsentsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if user exists
		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get user consents
		userConsents, err := database.GetConsentsByUserId(r.Context(), nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Load client details for consents
		err = database.UserConsentsLoadClients(r.Context(), nil, userConsents)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := api.GetUserConsentsResponse{
			Consents: apimapping.ToUserConsentResponses(userConsents),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleAPIUserConsentDelete(
	database userConsentsDatabase,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Consent ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		consentId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid consent ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get the consent to check if it exists and get user info for audit
		consent, err := database.GetUserConsentById(r.Context(), nil, consentId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if consent == nil {
			writeJSONError(w, "Consent not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the consent
		err = database.DeleteUserConsent(r.Context(), nil, consentId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.AuditDeletedUserConsent, map[string]interface{}{
			"userId":       consent.UserId,
			"consentId":    consentId,
			"loggedInUser": r.Context().Value("subject"),
		})

		response := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, response)
	}
}
