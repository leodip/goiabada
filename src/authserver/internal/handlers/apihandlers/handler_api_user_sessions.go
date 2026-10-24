package apihandlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// userSessionsDatabase is what the single session endpoint needs: the session named by its
// numeric id, and what buildSessionDetails reads to turn it into a list row.
type userSessionsDatabase interface {
	sessionDetailsDatabase

	GetUserSessionById(ctx context.Context, tx *sql.Tx, userSessionId int64) (*record.UserSession, error)
	UserSessionsLoadClients(ctx context.Context, tx *sql.Tx, userSessions []record.UserSession) error
}

// HandleUserSessionGet - GET /api/v1/admin/user-sessions/{id}
//
// The session is built by buildSessionDetails, the one function the three session lists build
// their rows through, so it reads the same here as in a list, and a session that function leaves
// out, one past the idle timeout or the maximum lifetime, is the same 404 as an id naming no
// session: the API names live sessions only, whatever the background worker has swept (#651
// decisions 4 and 6).
func HandleUserSessionGet(
	database userSessionsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get session ID from URL parameter
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "User session ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		sessionId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user session ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get user session from database
		userSession, err := database.GetUserSessionById(r.Context(), nil, sessionId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if userSession == nil {
			writeJSONError(w, "User session not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Load the clients the session authorized; buildSessionDetails hydrates them.
		userSessions := []record.UserSession{*userSession}
		err = database.UserSessionsLoadClients(r.Context(), nil, userSessions)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// The caller's own session, when its token names one, as on the session lists (#373
		// decision 1).
		currentSid := ""
		if jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context()); ok {
			currentSid = jwtToken.StringClaim("sid")
		}

		sessions, err := buildSessionDetails(r.Context(), database, userSessions, settings, currentSid)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if len(sessions) == 0 {
			writeJSONError(w, "User session not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create response
		response := api.GetUserSessionResponse{
			Session: sessions[0],
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}
