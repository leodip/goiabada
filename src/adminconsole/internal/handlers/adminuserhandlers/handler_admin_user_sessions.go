package adminuserhandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// userSessionsAPI is what the user sessions page needs: the user, its sessions, and the revoke of
// one.
type userSessionsAPI interface {
	DeleteUserSessionById(ctx context.Context, accessToken string, sessionId int64) error
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
	GetUserSessionsByUserId(ctx context.Context, accessToken string, userId int64) ([]api.UserSessionDetailResponse, error)
}

func HandleSessionsGet(
	httpHelper HttpHelper,
	apiClient userSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
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
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get the user's sessions via API
		sessions, err := apiClient.GetUserSessionsByUserId(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sessionInfoArr := render.SessionInfos(sessions)

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

func HandleSessionsPost(
	httpHelper HttpHelper,
	apiClient userSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		// Verify user exists via API
		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}
		if user == nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if decodeErr := decoder.Decode(&data); decodeErr != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		userSessionId, ok := data["userSessionId"].(float64)
		if !ok || userSessionId == 0 {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Whether the row being deleted is the caller's own is a field on that row. The auth
		// server computes isCurrent from the sid claim of the very token this request forwards,
		// so this is the same comparison the console used to make for itself, now made once and
		// in one place (#373).
		sessions, err := apiClient.GetUserSessionsByUserId(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
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
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		// Delete the user session via API
		err = apiClient.DeleteUserSessionById(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(userSessionId))
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
