package adminclienthandlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminClientUserSessionsGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Load client via API
		clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get the first 50 sessions (server filters invalid)
		clientSessions, err := apiClient.GetClientSessionsByClientId(jwtInfo.TokenResponse.AccessToken, clientResp.Id, 1, 50)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// The owners arrive with the sessions, so this page no longer reads a user per row: at a
		// full page that was 50 HTTP round trips to fill two columns (#373 decision 9).
		owners := make(map[int64]api.SessionOwnerResponse, len(clientSessions.Users))
		for _, owner := range clientSessions.Users {
			owners[owner.Id] = owner
		}

		// IsCurrent comes from the response; this page no longer recomputes it from the sid on
		// the console's own access token, which is the claim the auth server now reads (#373).
		sessionInfoArr := []SessionInfo{}
		for _, es := range clientSessions.Sessions {
			usi := SessionInfo{
				UserSessionId: es.Id,
				IsCurrent:     es.IsCurrent,
				UserId:        es.UserId,
				UserEmail:     "",
				UserFullName:  "",
				Started:       es.Started,
				LastAccessed:  es.LastAccessed,
				IpAddress:     es.IpAddress,
				DeviceName:    es.DeviceName,
				DeviceType:    es.DeviceType,
				DeviceOS:      es.DeviceOS,
				UserAgent:     es.UserAgent,
				Clients:       es.ClientIdentifiers,
			}
			if owner, ok := owners[es.UserId]; ok {
				usi.UserEmail = owner.Email
				usi.UserFullName = handlers.SessionOwnerFullName(&owner)
			}
			sessionInfoArr = append(sessionInfoArr, usi)
		}

		sort.Slice(sessionInfoArr, func(i, j int) bool {
			return sessionInfoArr[i].UserSessionId > sessionInfoArr[j].UserSessionId
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

func HandleAdminClientUserSessionsPost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}
		clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		userSessionId, ok := data["userSessionId"].(float64)
		if !ok || userSessionId == 0 {
			handlers.JsonBadRequestBody(httpHelper, w, r)
			return
		}

		// Whether the row being deleted is the caller's own is a field on that row. The auth
		// server computes isCurrent from the sid claim of the very token this request forwards,
		// so this is the same comparison the console used to make for itself, now made once and
		// in one place (#373).
		//
		// The page this request comes from is the first 50 rows, so the same page is read back.
		clientSessions, err := apiClient.GetClientSessionsByClientId(jwtInfo.TokenResponse.AccessToken, clientResp.Id, 1, 50)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		isDeletingCurrentSession := false
		for _, es := range clientSessions.Sessions {
			if es.Id == int64(userSessionId) && es.IsCurrent {
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
			httpHelper.EncodeJson(w, r, result)
			return
		}

		// Delete the session via API (authserver performs audit)
		err = apiClient.DeleteUserSessionById(jwtInfo.TokenResponse.AccessToken, int64(userSessionId))
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
