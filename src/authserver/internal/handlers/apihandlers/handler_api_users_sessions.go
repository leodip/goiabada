package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
)

// usersSessionsDatabase is what the administrator's user session endpoints need: one user's
// sessions.
//
// It embeds the row builder's port because the listing is built by buildSessionDetails, and the
// revocation port because terminating a session goes through handlers.TerminateUserSessionTx.
type usersSessionsDatabase interface {
	sessionDetailsDatabase
	handlers.RevocationDatabase

	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUserSessionById(ctx context.Context, tx *sql.Tx, userSessionId int64) (*models.UserSession, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserSession, error)
	UserSessionsLoadClients(ctx context.Context, tx *sql.Tx, userSessions []models.UserSession) error
}

// HandleAPIUserSessionsGet - GET /api/v1/admin/users/{id}/sessions
func HandleAPIUserSessionsGet(
	database usersSessionsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
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

		// Get user sessions
		userSessions, err := database.GetUserSessionsByUserId(r.Context(), nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Load the clients each session authorized; buildSessionDetails hydrates them.
		err = database.UserSessionsLoadClients(r.Context(), nil, userSessions)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		// The caller's own session, when its token names one. An admin token minted through
		// client_credentials carries no sid and correctly gets isCurrent false throughout; a
		// user-bound admin token gets true on its own row, which is the same answer the admin
		// console used to compute for itself from the same claim (#373 decision 1).
		currentSid := ""
		if jwtToken, ok := middleware.GetValidatedToken(r); ok {
			currentSid = jwtToken.GetStringClaim("sid")
		}

		sessions, err := buildSessionDetails(r.Context(), database, userSessions, settings, currentSid)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := api.GetUserSessionsResponse{
			Sessions: sessions,
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleAPIUserSessionDelete - DELETE /api/v1/admin/user-sessions/{id}
func HandleAPIUserSessionDelete(
	database usersSessionsDatabase,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get session ID from URL parameter
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "User session ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		sessionId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user session ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if session exists
		userSession, err := database.GetUserSessionById(r.Context(), nil, sessionId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if userSession == nil {
			writeJSONError(w, "User session not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Terminate the session rather than merely deleting it: this is the explicit
		// administrative "end this session" action, so it also marks the codes issued through the
		// session revoked and sweeps the refresh tokens those grants produced, all in one
		// transaction (#129 decision 5). The 404 above answers first, so a missing session never
		// opens one.
		result, err := handlers.TerminateUserSessionTx(r.Context(), database, userSession)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Both events, after the commit, neither on the error path above: an audited termination
		// that rolled back would be a false record. deleted_user_session keeps its existing
		// payload untouched and terminated_user_session carries the security detail (decision 9).
		loggedInUser := callerSubject(r)
		auditLogger.Log(r.Context(), audit.AuditDeletedUserSession, map[string]interface{}{
			"userSessionId": sessionId,
			"loggedInUser":  loggedInUser,
		})
		handlers.LogTerminatedUserSession(r.Context(), auditLogger, userSession, loggedInUser, result)

		// Return success response
		response := api.SuccessResponse{
			Success: true,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
