package apihandlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPIUserSessionsGet - GET /api/v1/admin/users/{id}/sessions
func HandleAPIUserSessionsGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "User ID is required", "USER_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "INVALID_USER_ID", http.StatusBadRequest)
			return
		}

		// Check if user exists
		user, err := database.GetUserById(nil, id)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Get user sessions
		userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Load client information for sessions
		err = database.UserSessionsLoadClients(nil, userSessions)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Get settings for session validation
		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// Build enhanced session responses
		enhancedSessions := make([]api.EnhancedUserSessionResponse, 0)
		for _, us := range userSessions {
			// Check if session is valid based on timeout settings
			isValid := us.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)

			// Skip invalid sessions (following the original logic)
			if !isValid {
				continue
			}

			enhancedSession := api.EnhancedUserSessionResponse{
				Id:                         us.Id,
				SessionIdentifier:          us.SessionIdentifier,
				AuthMethods:                us.AuthMethods,
				AcrLevel:                   us.AcrLevel,
				IpAddress:                  us.IpAddress,
				DeviceName:                 us.DeviceName,
				DeviceType:                 us.DeviceType,
				DeviceOS:                   us.DeviceOS,
				Level2AuthConfigHasChanged: us.Level2AuthConfigHasChanged,
				UserId:                     us.UserId,
				IsValid:                    isValid,
			}

			// Set time fields
			if us.CreatedAt.Valid {
				enhancedSession.CreatedAt = &us.CreatedAt.Time
			}
			if us.UpdatedAt.Valid {
				enhancedSession.UpdatedAt = &us.UpdatedAt.Time
			}
			if !us.Started.IsZero() {
				enhancedSession.Started = &us.Started
				enhancedSession.StartedAt = us.Started.Format(time.RFC1123)
				enhancedSession.DurationSinceStarted = time.Now().UTC().Sub(us.Started).Round(time.Second).String()
			}
			if !us.LastAccessed.IsZero() {
				enhancedSession.LastAccessed = &us.LastAccessed
				enhancedSession.LastAccessedAt = us.LastAccessed.Format(time.RFC1123)
				enhancedSession.DurationSinceLastAccessed = time.Now().UTC().Sub(us.LastAccessed).Round(time.Second).String()
			}
			if !us.AuthTime.IsZero() {
				enhancedSession.AuthTime = &us.AuthTime
			}

			// Load client information
			err = database.UserSessionClientsLoadClients(nil, us.Clients)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			// Extract client identifiers
			clientIdentifiers := make([]string, 0)
			for _, usc := range us.Clients {
				clientIdentifiers = append(clientIdentifiers, usc.Client.ClientIdentifier)
			}
			enhancedSession.ClientIdentifiers = clientIdentifiers

			enhancedSessions = append(enhancedSessions, enhancedSession)
		}

		// Create response
		response := api.GetUserSessionsResponse{
			Sessions: enhancedSessions,
		}

		// Set content type and encode response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIUserSessionDelete - DELETE /api/v1/admin/user-sessions/{id}
func HandleAPIUserSessionDelete(
	database data.Database,
	authHelper handlers.AuthHelper,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get session ID from URL parameter
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "User session ID is required", "USER_SESSION_ID_REQUIRED", http.StatusBadRequest)
			return
		}

		sessionId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user session ID format", "INVALID_USER_SESSION_ID", http.StatusBadRequest)
			return
		}

		// Check if session exists
		userSession, err := database.GetUserSessionById(nil, sessionId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if userSession == nil {
			writeJSONError(w, "User session not found", "USER_SESSION_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Delete the user session
		err = database.DeleteUserSession(nil, sessionId)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		// Log audit event
		auditLogger.Log(constants.AuditDeletedUserSession, map[string]interface{}{
			"userSessionId": sessionId,
			"loggedInUser":  authHelper.GetLoggedInSubject(r),
		})

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}
