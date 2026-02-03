package accounthandlers

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAccountSessionsGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Fetch sessions via API
		enhancedSessions, err := apiClient.GetAccountSessions(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sessionInfoArr := []SessionInfo{}
		for _, es := range enhancedSessions {
			usi := SessionInfo{
				UserSessionId:             es.Id,
				StartedAt:                 es.StartedAt,
				DurationSinceStarted:      es.DurationSinceStarted,
				LastAcessedAt:             es.LastAccessedAt,
				DurationSinceLastAccessed: es.DurationSinceLastAccessed,
				IpAddress:                 es.IpAddress,
				DeviceName:                es.DeviceName,
				DeviceType:                es.DeviceType,
				DeviceOS:                  es.DeviceOS,
				Clients:                   es.ClientIdentifiers,
				IsCurrent:                 es.IsCurrent,
			}
			sessionInfoArr = append(sessionInfoArr, usi)
		}

		sort.Slice(sessionInfoArr, func(i, j int) bool {
			return sessionInfoArr[i].UserSessionId > sessionInfoArr[j].UserSessionId
		})

		bind := map[string]interface{}{
			"sessions":  sessionInfoArr,
			"csrfField": csrf.TemplateField(r),
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			httpHelper.JsonError(w, r, errors.Wrap(err, "could not decode request body"))
			return
		}

		userSessionId, ok := data["userSessionId"].(float64)
		if !ok || userSessionId == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("could not find user session id to revoke")))
			return
		}

		// Check if we're deleting the current session
		currentSessionIdentifier := ""
		if jwtInfo.AccessToken != nil {
			currentSessionIdentifier = jwtInfo.AccessToken.GetStringClaim("sid")
		}

		isDeletingCurrentSession := false
		if currentSessionIdentifier != "" {
			// Fetch sessions to check if the session being deleted is the current one
			enhancedSessions, err := apiClient.GetAccountSessions(jwtInfo.TokenResponse.AccessToken)
			if err == nil {
				for _, es := range enhancedSessions {
					if es.Id == int64(userSessionId) && es.SessionIdentifier == currentSessionIdentifier {
						isDeletingCurrentSession = true
						break
					}
				}
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
		if err := apiClient.DeleteAccountSession(jwtInfo.TokenResponse.AccessToken, int64(userSessionId)); err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		result := struct{ Success bool }{Success: true}
		httpHelper.EncodeJson(w, r, result)
	}
}
