package apihandlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
)

// HandleAPIClientSessionsGet - GET /api/v1/admin/clients/{id}/sessions
// Returns a paginated list of user sessions associated with a client, and the people they
// belong to. Defaults: page=1, size=50. Caps size to 100. Lists only sessions still active
// under the current settings; an expired one is omitted rather than reported (#373 decision 2).
//
// This is the one session list spanning users, so the console could not name a session's owner
// without reading each one back: it fetched a user per row, up to 50 HTTP round trips to render
// one page. The owners ride along in a normalized users array instead (#373 decision 9).
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

		users, err := sessionOwners(database, sessions)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		response := api.GetClientSessionsResponse{
			Sessions: sessions,
			Users:    users,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// sessionOwners resolves the people the given sessions belong to, in one query, and answers a
// normalized array: a user holding several sessions appears once. The order is the order the
// sessions first name each id rather than the map's, because a map's iteration order is random
// and the response is something a wire-bytes case has to be able to write down.
//
// Never nil: the schema declares users a required array, and a nil slice marshals to null, which
// is not an empty array to anything reading the document -- the same invariant the mapper keeps
// for clientIdentifiers.
//
// A session naming a user with no row is refused rather than answered with the owner silently
// missing, for the reason loadSessionClients refuses a client id with no row: user_sessions.user_id
// is a non-null foreign key, so an unresolvable one is a broken row and a page rendering a blank
// email in its place would hide it.
func sessionOwners(database data.Database, sessions []api.UserSessionDetailResponse) ([]api.SessionOwnerResponse, error) {
	userIds := make([]int64, 0, len(sessions))
	seen := make(map[int64]bool, len(sessions))
	for _, session := range sessions {
		if !seen[session.UserId] {
			seen[session.UserId] = true
			userIds = append(userIds, session.UserId)
		}
	}
	if len(userIds) == 0 {
		return []api.SessionOwnerResponse{}, nil
	}

	usersById, err := database.GetUsersByIds(nil, userIds)
	if err != nil {
		return nil, errs.Wrap(err, "unable to get users by ids")
	}

	ordered := make([]models.User, 0, len(userIds))
	for _, userId := range userIds {
		user, ok := usersById[userId]
		if !ok {
			return nil, errs.Errorf("user with id %d not found", userId)
		}
		ordered = append(ordered, user)
	}

	return apimapping.ToSessionOwnerResponses(ordered), nil
}
