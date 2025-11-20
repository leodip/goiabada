package adminclienthandlers

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sort"
    "strconv"

    "github.com/pkg/errors"

    "github.com/go-chi/chi/v5"
    "github.com/gorilla/csrf"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
)

func HandleAdminClientUserSessionsGet(
    httpHelper handlers.HttpHelper,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

        idStr := chi.URLParam(r, "clientId")
        if len(idStr) == 0 {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
            return
        }

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        // Load client via API
        clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }
        if clientResp == nil {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

        // Get the first 50 sessions (server filters invalid)
        enhancedSessions, err := apiClient.GetClientSessionsByClientId(jwtInfo.TokenResponse.AccessToken, clientResp.Id, 1, 50)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
            return
        }

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

        sessionInfoArr := []SessionInfo{}
        for _, es := range enhancedSessions {
            // N+1: fetch user for email/full name
            user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, es.UserId)
            if err != nil {
                handlers.HandleAPIError(httpHelper, w, r, err)
                return
            }
            usi := SessionInfo{
                UserSessionId:             es.Id,
                UserId:                    es.UserId,
                UserEmail:                 "",
                UserFullName:              "",
                StartedAt:                 es.StartedAt,
                DurationSinceStarted:      es.DurationSinceStarted,
                LastAcessedAt:             es.LastAccessedAt,
                DurationSinceLastAccessed: es.DurationSinceLastAccessed,
                IpAddress:                 es.IpAddress,
                DeviceName:                es.DeviceName,
                DeviceType:                es.DeviceType,
                DeviceOS:                  es.DeviceOS,
                Clients:                   es.ClientIdentifiers,
            }
            if user != nil {
                usi.UserEmail = user.Email
                usi.UserFullName = user.GetFullName()
            }
            if es.SessionIdentifier == sessionIdentifier {
                usi.IsCurrent = true
            }
            sessionInfoArr = append(sessionInfoArr, usi)
        }

		sort.Slice(sessionInfoArr, func(i, j int) bool {
			return sessionInfoArr[i].UserSessionId > sessionInfoArr[j].UserSessionId
		})

        bind := map[string]interface{}{
            "client":    clientResp,
            "sessions":  sessionInfoArr,
            "csrfField": csrf.TemplateField(r),
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
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

        id, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            httpHelper.InternalServerError(w, r, err)
            return
        }
        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }
        clientResp, err := apiClient.GetClientById(jwtInfo.TokenResponse.AccessToken, id)
        if err != nil {
            httpHelper.JsonError(w, r, err)
            return
        }
        if clientResp == nil {
            httpHelper.JsonError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
            return
        }

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
			httpHelper.JsonError(w, r, err)
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
			// Fetch sessions for this client to check if the session being deleted is the current one
			enhancedSessions, err := apiClient.GetClientSessionsByClientId(jwtInfo.TokenResponse.AccessToken, clientResp.Id, 1, 50)
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
				Success bool
				IsCurrentSession bool
			}{
				Success: true,
				IsCurrentSession: true,
			}
			httpHelper.EncodeJson(w, r, result)
			return
		}

        // Delete the session via API (authserver performs audit)
        err = apiClient.DeleteUserSessionById(jwtInfo.TokenResponse.AccessToken, int64(userSessionId))
        if err != nil {
            httpHelper.JsonError(w, r, err)
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
