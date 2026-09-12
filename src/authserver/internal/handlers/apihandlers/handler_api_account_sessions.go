package apihandlers

import (
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
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Load sessions
		userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Load nested client info (to collect client identifiers)
		if err := database.UserSessionsLoadClients(nil, userSessions); err != nil {
			writeInternalServerError(w, r, err)
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
				writeInternalServerError(w, r, err)
				return
			}

			enh := api.EnhancedUserSessionResponse{
				Id:                us.Id,
				SessionIdentifier: us.SessionIdentifier,
				AuthMethods:       us.AuthMethods,
				AcrLevel:          us.AcrLevel,
				IpAddress:         us.IpAddress,
				DeviceName:        us.DeviceName,
				DeviceType:        us.DeviceType,
				DeviceOS:          us.DeviceOS,
				UserAgent:         us.UserAgent,
				UserId:            us.UserId,
				IsValid:           isValid,
				IsCurrent:         currentSid != "" && us.SessionIdentifier == currentSid,
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
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAPIAccountSessionDelete - DELETE /api/v1/account/sessions/{id}
// Deletes a user session that belongs to the authenticated user. Deleting the
// current session is allowed.
func HandleAPIAccountSessionDelete(
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
			writeJSONError(w, "User session ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check that the session exists and belongs to the user
		us, err := database.GetUserSessionById(nil, sessionId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if us == nil {
			writeJSONError(w, "User session not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Resolve user and verify ownership
		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil || us.UserId != user.Id {
			writeJSONError(w, "Forbidden", "FORBIDDEN", http.StatusForbidden)
			return
		}

		// Terminate the session, including the current one, rather than merely deleting it: this is
		// the explicit self-service "end this session" action, so it also marks the codes issued
		// through the session revoked and sweeps the refresh tokens those grants produced, in one
		// transaction (#129 decision 5). The ownership check above answers 403 first, so this is
		// never reached for somebody else's session.
		result, err := handlers.TerminateUserSessionTx(database, us)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Both events, after the commit, neither on the error path above: an audited termination
		// that rolled back would be a false record. deleted_user_session keeps its existing
		// payload untouched and terminated_user_session carries the security detail (decision 9).
		loggedInUser := authHelper.GetLoggedInSubject(r)
		auditLogger.Log(r.Context(), constants.AuditDeletedUserSession, map[string]interface{}{
			"userSessionId": sessionId,
			"loggedInUser":  loggedInUser,
		})
		handlers.LogTerminatedUserSession(r.Context(), auditLogger, us, loggedInUser, result)

		// Success response
		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
