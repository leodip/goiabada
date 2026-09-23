package accounthandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// accountSessionsAPI is what the account sessions page needs: the list, and the revoke of one.
type accountSessionsAPI interface {
	DeleteAccountSession(ctx context.Context, accessToken string, sessionId int64) error
	GetAccountSessions(ctx context.Context, accessToken string) ([]api.UserSessionDetailResponse, error)
}

func HandleAccountSessionsGet(
	httpHelper handlers.HttpHelper,
	apiClient accountSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Fetch sessions via API
		sessions, err := apiClient.GetAccountSessions(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sessionInfoArr := []SessionInfo{}
		for _, es := range sessions {
			usi := SessionInfo{
				UserSessionId: es.Id,
				Started:       es.Started,
				LastAccessed:  es.LastAccessed,
				IpAddress:     es.IpAddress,
				DeviceName:    es.DeviceName,
				DeviceType:    es.DeviceType,
				DeviceOS:      es.DeviceOS,
				UserAgent:     es.UserAgent,
				Clients:       es.ClientIdentifiers,
				IsCurrent:     es.IsCurrent,
			}
			sessionInfoArr = append(sessionInfoArr, usi)
		}

		sort.Slice(sessionInfoArr, func(i, j int) bool {
			return sessionInfoArr[i].UserSessionId > sessionInfoArr[j].UserSessionId
		})

		bind := map[string]interface{}{
			"sessions": sessionInfoArr,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_user_sessions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountSessionsEndSesssionPost(
	httpHelper handlers.HttpHelper,
	apiClient accountSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
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
		sessions, err := apiClient.GetAccountSessions(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		isDeletingCurrentSession := false
		for _, es := range sessions {
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
			}{Success: true, IsCurrentSession: true}
			httpHelper.EncodeJson(w, r, result)
			return
		}

		// Delete session via API (server validates ownership and audits)
		if err = apiClient.DeleteAccountSession(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(userSessionId)); err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		result := struct{ Success bool }{Success: true}
		httpHelper.EncodeJson(w, r, result)
	}
}
