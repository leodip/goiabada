package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// accountConsentsDatabase is what the account consent endpoints need: the caller's consents and
// the clients they name.
type accountConsentsDatabase interface {
	DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentId int64) error
	GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserConsent, error)
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserConsentById(ctx context.Context, tx *sql.Tx, userConsentId int64) (*record.UserConsent, error)
	UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error
}

// GET /api/v1/account/consents
func HandleAccountConsentsGet(
	database accountConsentsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		consents, err := database.GetConsentsByUserId(r.Context(), nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if err := database.UserConsentsLoadClients(r.Context(), nil, consents); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		resp := api.GetUserConsentsResponse{Consents: apimapping.ToUserConsentResponses(consents)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// DELETE /api/v1/account/consents/{id}
func HandleAccountConsentDelete(
	database accountConsentsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

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

		consent, err := database.GetUserConsentById(r.Context(), nil, consentId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if consent == nil {
			writeJSONError(w, "Consent not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Ownership check: must belong to current user
		if consent.UserId != user.Id {
			writeJSONError(w, "Forbidden", "FORBIDDEN", http.StatusForbidden)
			return
		}

		if err := database.DeleteUserConsent(r.Context(), nil, consentId); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		auditLogger.Log(r.Context(), audit.EventDeletedOwnUserConsent, map[string]interface{}{
			"user_id":        user.Id,
			"consent_id":     consentId,
			"logged_in_user": subject,
		})

		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
