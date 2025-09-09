package apihandlers

import (
    "encoding/json"
    "net/http"
    "strconv"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/authserver/internal/middleware"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/models"
)

// HandleAPIAccountSessionsGet - GET /api/v1/account/sessions
// Returns the current user's valid sessions with enhanced details.
func HandleAPIAccountSessionsGet(
    httpHelper handlers.HttpHelper,
    database data.Database,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract validated access token (auth and scope enforced by middleware)
        jwtToken, ok := middleware.GetValidatedToken(r)
        if !ok {
            writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
            return
        }

        subject := jwtToken.GetStringClaim("sub")
        if subject == "" {
            writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
            return
        }

        // Resolve user by subject
        user, err := database.GetUserBySubject(nil, subject)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if user == nil {
            writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
            return
        }

        // Load sessions
        userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        // Load nested client info (to collect client identifiers)
        if err := database.UserSessionsLoadClients(nil, userSessions); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
        currentSid := jwtToken.GetStringClaim("sid")

        enhanced := make([]api.EnhancedUserSessionResponse, 0, len(userSessions))
        for _, us := range userSessions {
            // Filter using current global settings
            isValid := us.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
            if !isValid {
                continue
            }

            // Ensure clients on session are also loaded
            if err := database.UserSessionClientsLoadClients(nil, us.Clients); err != nil {
                writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
                return
            }

            enh := api.EnhancedUserSessionResponse{
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
                IsCurrent:                  currentSid != "" && us.SessionIdentifier == currentSid,
            }

            if us.CreatedAt.Valid {
                enh.CreatedAt = &us.CreatedAt.Time
            }
            if us.UpdatedAt.Valid {
                enh.UpdatedAt = &us.UpdatedAt.Time
            }
            if !us.Started.IsZero() {
                enh.Started = &us.Started
                enh.StartedAt = us.Started.Format(time.RFC1123)
                enh.DurationSinceStarted = time.Now().UTC().Sub(us.Started).Round(time.Second).String()
            }
            if !us.LastAccessed.IsZero() {
                enh.LastAccessed = &us.LastAccessed
                enh.LastAccessedAt = us.LastAccessed.Format(time.RFC1123)
                enh.DurationSinceLastAccessed = time.Now().UTC().Sub(us.LastAccessed).Round(time.Second).String()
            }
            if !us.AuthTime.IsZero() {
                enh.AuthTime = &us.AuthTime
            }

            // Collect client identifiers
            clientIdentifiers := make([]string, 0, len(us.Clients))
            for _, usc := range us.Clients {
                clientIdentifiers = append(clientIdentifiers, usc.Client.ClientIdentifier)
            }
            enh.ClientIdentifiers = clientIdentifiers

            enhanced = append(enhanced, enh)
        }

        resp := api.GetUserSessionsResponse{Sessions: enhanced}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}

// HandleAPIAccountSessionDelete - DELETE /api/v1/account/sessions/{id}
// Deletes a user session that belongs to the authenticated user. Deleting the
// current session is allowed.
func HandleAPIAccountSessionDelete(
    httpHelper handlers.HttpHelper,
    database data.Database,
    authHelper handlers.AuthHelper,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Extract token and subject
        jwtToken, ok := middleware.GetValidatedToken(r)
        if !ok {
            writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
            return
        }
        subject := jwtToken.GetStringClaim("sub")
        if subject == "" {
            writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
            return
        }

        // Parse session ID from URL
        sessionIdStr := chi.URLParam(r, "id")
        sessionId, err := strconv.ParseInt(sessionIdStr, 10, 64)
        if err != nil || sessionId <= 0 {
            writeJSONError(w, "User session ID is required", "USER_SESSION_ID_REQUIRED", http.StatusBadRequest)
            return
        }

        // Check that the session exists and belongs to the user
        us, err := database.GetUserSessionById(nil, sessionId)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if us == nil {
            writeJSONError(w, "User session not found", "USER_SESSION_NOT_FOUND", http.StatusNotFound)
            return
        }

        // Resolve user and verify ownership
        user, err := database.GetUserBySubject(nil, subject)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if user == nil || us.UserId != user.Id {
            writeJSONError(w, "Forbidden", "FORBIDDEN", http.StatusForbidden)
            return
        }

        // Delete session (including current, allowed)
        if err := database.DeleteUserSession(nil, sessionId); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit
        auditLogger.Log(constants.AuditDeletedUserSession, map[string]interface{}{
            "userSessionId": sessionId,
            "loggedInUser":  authHelper.GetLoggedInSubject(r),
        })

        // Success response
        resp := api.SuccessResponse{Success: true}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}
