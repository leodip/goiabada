package apihandlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
)

// HandleAPIUserSessionGet - GET /api/v1/admin/user-sessions/{sessionIdentifier}
func HandleAPIUserSessionGet(
	database data.Database,
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
		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
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
			Session: *api.ToUserSessionResponse(userSession),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}
