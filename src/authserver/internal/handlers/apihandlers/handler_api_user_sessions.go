package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
)

// HandleAPIUserSessionGet - GET /api/v1/admin/user-sessions/{sessionIdentifier}
func HandleAPIUserSessionGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get session identifier from URL parameter
		sessionIdentifier := chi.URLParam(r, "sessionIdentifier")
		if sessionIdentifier == "" {
			writeJSONError(w, "Session identifier is required", "SESSION_IDENTIFIER_REQUIRED", http.StatusBadRequest)
			return
		}

		// Get user session from database
		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if userSession == nil {
			writeJSONError(w, "User session not found", "USER_SESSION_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create response
		response := api.GetUserSessionResponse{
			Session: *api.ToUserSessionResponse(userSession),
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserSessionPut - PUT /api/v1/admin/user-sessions/{sessionIdentifier}
func HandleAPIUserSessionPut(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get session identifier from URL parameter
		sessionIdentifier := chi.URLParam(r, "sessionIdentifier")
		if sessionIdentifier == "" {
			writeJSONError(w, "Session identifier is required", "SESSION_IDENTIFIER_REQUIRED", http.StatusBadRequest)
			return
		}

		// Decode the request body
		var req api.UpdateUserSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get existing user session
		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if userSession == nil {
			writeJSONError(w, "User session not found", "USER_SESSION_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Update fields if provided
		if req.Level2AuthConfigHasChanged != nil {
			userSession.Level2AuthConfigHasChanged = *req.Level2AuthConfigHasChanged
		}

		// Update user session in database
		err = database.UpdateUserSession(nil, userSession)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Get the updated session to return
		updatedSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Create response
		response := api.GetUserSessionResponse{
			Session: *api.ToUserSessionResponse(updatedSession),
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}