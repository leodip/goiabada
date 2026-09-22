package adminuserhandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// userSessionsAPI is what the user sessions page needs: the user, its sessions, and the revoke of
// one.
type userSessionsAPI interface {
	DeleteUserSessionById(ctx context.Context, accessToken string, sessionId int64) error
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	GetUserSessionsByUserId(ctx context.Context, accessToken string, userId int64) ([]api.UserSessionDetailResponse, error)
}

func HandleAdminUserSessionsGet(
	httpHelper handlers.HttpHelper,
	apiClient userSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get user details via API
		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get the user's sessions via API
		sessions, err := apiClient.GetUserSessionsByUserId(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// IsCurrent comes from the response. This page used to recompute it by comparing each
		// row's sessionIdentifier against the sid the console lifted off its own access token,
		// which is the same claim the auth server now reads, so the value is unchanged and there
		// is one place left that decides it (#373).
		sessionInfoArr := []SessionInfo{}
		for _, es := range sessions {
			sessionInfoArr = append(sessionInfoArr, SessionInfo{
				UserSessionId: es.Id,
				IsCurrent:     es.IsCurrent,
				Started:       es.Started,
				LastAccessed:  es.LastAccessed,
				IpAddress:     es.IpAddress,
				DeviceName:    es.DeviceName,
				DeviceType:    es.DeviceType,
				DeviceOS:      es.DeviceOS,
				UserAgent:     es.UserAgent,
				Clients:       es.ClientIdentifiers,
			})
		}

		sort.Slice(sessionInfoArr, func(i, j int) bool {
			return sessionInfoArr[i].UserSessionId > sessionInfoArr[j].UserSessionId
		})

		bind := map[string]interface{}{
			"user":     user,
			"sessions": sessionInfoArr,
			"page":     r.URL.Query().Get("page"),
			"query":    r.URL.Query().Get("query"),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_sessions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserSessionsPost(
	httpHelper handlers.HttpHelper,
	apiClient userSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		// Verify user exists via API
		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if user == nil {
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
		sessions, err := apiClient.GetUserSessionsByUserId(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
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
			}{
				Success:          true,
				IsCurrentSession: true,
			}
			httpHelper.EncodeJson(w, r, result)
			return
		}

		// Delete the user session via API
		err = apiClient.DeleteUserSessionById(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(userSessionId))
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
