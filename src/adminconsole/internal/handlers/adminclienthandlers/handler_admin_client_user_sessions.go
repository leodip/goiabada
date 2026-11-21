package adminclienthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// clientSessionsAPI is what the client sessions page needs: the client, its sessions, and the
// revoke of one.
type clientSessionsAPI interface {
	DeleteUserSessionByID(ctx context.Context, accessToken string, sessionID int64) error
	GetClientByID(ctx context.Context, accessToken string, clientID int64) (*api.ClientResponse, error)
	GetClientSessionsByClientID(ctx context.Context, accessToken string, clientID int64, page, size int) (*api.GetClientSessionsResponse, error)
}

func HandleUserSessionsGet(
	httpHelper HTTPHelper,
	apiClient clientSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		// Load client via API
		clientResp, err := apiClient.GetClientByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get the first 50 sessions (server filters invalid)
		clientSessions, err := apiClient.GetClientSessionsByClientID(r.Context(), jwtInfo.TokenResponse.AccessToken, clientResp.ID, 1, 50)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// The owners arrive with the sessions, so this page no longer reads a user per row: at a
		// full page that was 50 HTTP round trips to fill two columns (#373 decision 9).
		owners := make(map[int64]api.SessionOwnerResponse, len(clientSessions.Users))
		for _, owner := range clientSessions.Users {
			owners[owner.ID] = owner
		}

		// IsCurrent comes from the response; this page no longer recomputes it from the sid on
		// the console's own access token, which is the claim the auth server now reads (#373).
		sessionInfoArr := []SessionInfo{}
		for _, es := range clientSessions.Sessions {
			usi := SessionInfo{
				UserSessionID: es.ID,
				IsCurrent:     es.IsCurrent,
				UserID:        es.UserID,
				UserEmail:     "",
				UserFullName:  "",
				Started:       es.Started,
				LastAccessed:  es.LastAccessed,
				IPAddress:     es.IPAddress,
				DeviceName:    es.DeviceName,
				DeviceType:    es.DeviceType,
				DeviceOS:      es.DeviceOS,
				UserAgent:     es.UserAgent,
				Clients:       es.ClientIdentifiers,
			}
			if owner, ok := owners[es.UserID]; ok {
				usi.UserEmail = owner.Email
				usi.UserFullName = render.SessionOwnerFullName(&owner)
			}
			sessionInfoArr = append(sessionInfoArr, usi)
		}

		sort.Slice(sessionInfoArr, func(i, j int) bool {
			a, b := sessionInfoArr[i], sessionInfoArr[j]
			return render.SessionListedBefore(a.IsCurrent, a.LastAccessed, a.UserSessionID, b.IsCurrent, b.LastAccessed, b.UserSessionID)
		})

		bind := map[string]interface{}{
			"client":   clientResp,
			"sessions": sessionInfoArr,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_usersessions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleUserSessionsPost(
	httpHelper HTTPHelper,
	apiClient clientSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("clientId")
		if len(idStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJWTInfo)
			return
		}
		clientResp, err := apiClient.GetClientByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if decodeErr := decoder.Decode(&data); decodeErr != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		userSessionID, ok := data["userSessionId"].(float64)
		if !ok || userSessionID == 0 {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Whether the row being deleted is the caller's own is a field on that row. The auth
		// server computes isCurrent from the sid claim of the very token this request forwards,
		// so this is the same comparison the console used to make for itself, now made once and
		// in one place (#373).
		//
		// The page this request comes from is the first 50 rows, so the same page is read back.
		clientSessions, err := apiClient.GetClientSessionsByClientID(r.Context(), jwtInfo.TokenResponse.AccessToken, clientResp.ID, 1, 50)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		isDeletingCurrentSession := false
		for _, es := range clientSessions.Sessions {
			if es.ID == int64(userSessionID) && es.IsCurrent {
				isDeletingCurrentSession = true
				break
			}
		}

		// If deleting the current session, return special response to trigger logout
		if isDeletingCurrentSession {
			// Return special response telling frontend to redirect to logout endpoint
			// This ensures proper logout flow with auth server
			result := struct {
				Success          bool
				IsCurrentSession bool
			}{
				Success:          true,
				IsCurrentSession: true,
			}
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		// Delete the session via API (authserver performs audit)
		err = apiClient.DeleteUserSessionByID(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(userSessionID))
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJSON(w, r, result)
	}
}
