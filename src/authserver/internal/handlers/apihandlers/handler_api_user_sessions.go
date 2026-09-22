package apihandlers

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
)

// userSessionsDatabase is what the single session endpoint needs: the session named by an
// identifier.
type userSessionsDatabase interface {
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
}

// HandleAPIUserSessionGet - GET /api/v1/admin/user-sessions/{sessionIdentifier}
func HandleAPIUserSessionGet(
	database userSessionsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get session identifier from URL parameter
		sessionIdentifier := chi.URLParam(r, "sessionIdentifier")
		if sessionIdentifier == "" {
			writeJSONError(w, "Session identifier is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get user session from database
		userSession, err := database.GetUserSessionBySessionIdentifier(r.Context(), nil, sessionIdentifier)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if userSession == nil {
			writeJSONError(w, "User session not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create response
		response := api.GetUserSessionResponse{
			Session: *apimapping.ToUserSessionResponse(userSession),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}
