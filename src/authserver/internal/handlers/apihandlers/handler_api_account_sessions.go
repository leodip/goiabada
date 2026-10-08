package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/api"
)

// accountSessionsDatabase is what the account session endpoints need: the caller's own sessions.
//
// It embeds the row builder's port because the listing is built by buildSessionDetails, and the
// revocation port because terminating a session goes through revocation.TerminateUserSessionTx.
type accountSessionsDatabase interface {
	sessionDetailsDatabase
	revocation.Database

	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserSessionById(ctx context.Context, tx *sql.Tx, userSessionId int64) (*record.UserSession, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error)
	UserSessionsLoadClients(ctx context.Context, tx *sql.Tx, userSessions []record.UserSession) error
}

// HandleAccountSessionsGet - GET /api/v1/account/sessions
// Returns the caller's own active sessions, each with the clients it authorized and
// whether it is the session the caller's own token was issued through.
func HandleAccountSessionsGet(
	database accountSessionsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtToken, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		// Resolve user by subject
		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Load sessions
		userSessions, err := database.GetUserSessionsByUserId(r.Context(), nil, user.Id)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Load the clients each session authorized; buildSessionDetails hydrates them.
		if userSessionsLoadClientsErr := database.UserSessionsLoadClients(r.Context(), nil, userSessions); userSessionsLoadClientsErr != nil {
			writeInternalServerError(w, r, userSessionsLoadClientsErr)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// This endpoint is the one that always had isCurrent; the two admin ones now read the
		// same claim through the same mapper (#373 decision 1).
		currentSid := jwtToken.StringClaim("sid")

		sessions, err := buildSessionDetails(r.Context(), database, userSessions, settings, currentSid)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		resp := api.GetUserSessionsResponse{Sessions: sessions}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleAccountSessionDelete - DELETE /api/v1/account/sessions/{id}
// Deletes a user session that belongs to the authenticated user. Deleting the
// current session is allowed.
func HandleAccountSessionDelete(
	database accountSessionsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
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
		us, err := database.GetUserSessionById(r.Context(), nil, sessionId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if us == nil {
			writeJSONError(w, "User session not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Resolve user and verify ownership
		user, err := database.GetUserBySubject(r.Context(), nil, subject)
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
		result, err := revocation.TerminateUserSessionTx(r.Context(), database, us)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Both events, after the commit, neither on the error path above: an audited termination
		// that rolled back would be a false record. deleted_user_session keeps its existing
		// payload untouched and terminated_user_session carries the security detail (decision 9).
		loggedInUser := callerSubject(r)
		auditLogger.Log(r.Context(), audit.EventDeletedUserSession, map[string]interface{}{
			"userSessionId": sessionId,
			"loggedInUser":  loggedInUser,
		})
		revocation.LogTerminatedUserSession(r.Context(), auditLogger, us, loggedInUser, result)

		// Success response
		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
