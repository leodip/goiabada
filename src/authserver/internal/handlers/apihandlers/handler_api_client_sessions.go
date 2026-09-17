package apihandlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPIClientSessionsGet - GET /api/v1/admin/clients/{id}/sessions
// Returns a paginated list of user sessions associated with a client.
// Defaults: page=1, size=50. Caps size to 100. Lists only sessions still active under the
// current settings; an expired one is omitted rather than reported (#373 decision 2).
func HandleAPIClientSessionsGet(
	database data.Database,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Parse client ID
		idStr := chi.URLParam(r, "id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		clientId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Ensure client exists
		client, err := database.GetClientById(nil, clientId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Pagination params
		page := 1
		size := 50
		if v := r.URL.Query().Get("page"); v != "" {
			if p, err := strconv.Atoi(v); err == nil && p > 0 {
				page = p
			}
		}
		if v := r.URL.Query().Get("size"); v != "" {
			if s, err := strconv.Atoi(v); err == nil && s > 0 {
				if s > 100 {
					s = 100
				}
				size = s
			}
		}

		// Fetch sessions linked to the client
		userSessions, _, err := database.GetUserSessionsByClientIdPaginated(nil, client.Id, page, size)
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

		// The caller's own session, when its token names one. See the same read in
		// handler_api_users_sessions.go: one mapper decides isCurrent for all three endpoints,
		// so it means the same thing here as it does there (#373 decision 1).
		currentSid := ""
		if jwtToken, ok := middleware.GetValidatedToken(r); ok {
			currentSid = jwtToken.GetStringClaim("sid")
		}

		sessions, err := buildSessionDetails(database, userSessions, settings, currentSid)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := api.GetUserSessionsResponse{
			Sessions: sessions,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
