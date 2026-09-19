package apihandlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
)

// HandleAPIAccountSessionsGet - GET /api/v1/account/sessions
// Returns the caller's own active sessions, each with the clients it authorized and
// whether it is the session the caller's own token was issued through.
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

		// Load the clients each session authorized; buildSessionDetails hydrates them.
		if err := database.UserSessionsLoadClients(nil, userSessions); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// This endpoint is the one that always had isCurrent; the two admin ones now read the
		// same claim through the same mapper (#373 decision 1).
		currentSid := jwtToken.GetStringClaim("sid")

		sessions, err := buildSessionDetails(database, userSessions, settings, currentSid)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		resp := api.GetUserSessionsResponse{Sessions: sessions}
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
		auditLogger.Log(r.Context(), audit.AuditDeletedUserSession, map[string]interface{}{
			"userSessionId": sessionId,
			"loggedInUser":  loggedInUser,
		})
		handlers.LogTerminatedUserSession(r.Context(), auditLogger, us, loggedInUser, result)

		// Success response
		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
