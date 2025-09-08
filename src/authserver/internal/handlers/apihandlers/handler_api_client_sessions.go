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

// HandleAPIClientSessionsGet - GET /api/v1/admin/clients/{id}/sessions
// Returns a paginated list of user sessions associated with a client.
// Defaults: page=1, size=50. Caps size to 100. Filters out invalid sessions.
func HandleAPIClientSessionsGet(
    httpHelper handlers.HttpHelper,
    database data.Database,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Authentication and authorization handled by middleware

        // Parse client ID
        idStr := chi.URLParam(r, "id")
        if idStr == "" {
            writeJSONError(w, "Client ID is required", "CLIENT_ID_REQUIRED", http.StatusBadRequest)
            return
        }
        clientId, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            writeJSONError(w, "Invalid client ID format", "INVALID_CLIENT_ID", http.StatusBadRequest)
            return
        }

        // Ensure client exists
        client, err := database.GetClientById(nil, clientId)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if client == nil {
            writeJSONError(w, "Client not found", "CLIENT_NOT_FOUND", http.StatusNotFound)
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
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        // Load clients for sessions to extract identifiers
        if err := database.UserSessionsLoadClients(nil, userSessions); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

        // Build enhanced session responses (no user details to keep API generic; callers can fetch users)
        enhanced := make([]api.EnhancedUserSessionResponse, 0, len(userSessions))
        for _, us := range userSessions {
            // Filter out invalid sessions per settings
            isValid := us.IsValid(settings.UserSessionIdleTimeoutInSeconds, settings.UserSessionMaxLifetimeInSeconds, nil)
            if !isValid {
                continue
            }

            // Ensure nested clients are loaded to fill client identifiers
            if err := database.UserSessionClientsLoadClients(nil, us.Clients); err != nil {
                writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
                return
            }

            enh := api.EnhancedUserSessionResponse{
                Id:                            us.Id,
                SessionIdentifier:             us.SessionIdentifier,
                AuthMethods:                   us.AuthMethods,
                AcrLevel:                      us.AcrLevel,
                IpAddress:                     us.IpAddress,
                DeviceName:                    us.DeviceName,
                DeviceType:                    us.DeviceType,
                DeviceOS:                      us.DeviceOS,
                Level2AuthConfigHasChanged:    us.Level2AuthConfigHasChanged,
                UserId:                        us.UserId,
                IsValid:                       isValid,
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

        response := api.GetUserSessionsResponse{
            Sessions: enhanced,
        }

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        if err := json.NewEncoder(w).Encode(response); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}

