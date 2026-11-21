package adminuserhandlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// userSessionsAPI is what the user sessions page needs: the user, its sessions, and the revoke of
// one.
type userSessionsAPI interface {
	DeleteUserSessionByID(ctx context.Context, accessToken string, sessionID int64) error
	GetUserByID(ctx context.Context, accessToken string, userID int64) (*api.UserResponse, error)
	GetUserSessionsByUserID(ctx context.Context, accessToken string, userID int64) ([]api.UserSessionDetailResponse, error)
}

func HandleSessionsGet(
	httpHelper HTTPHelper,
	apiClient userSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		idStr := r.PathValue("userId")
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
		user, err := apiClient.GetUserByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get the user's sessions via API
		sessions, err := apiClient.GetUserSessionsByUserID(r.Context(), jwtInfo.TokenResponse.AccessToken, user.ID)
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
	httpHelper HTTPHelper,
	apiClient userSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		idStr := r.PathValue("userId")
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
		user, err := apiClient.GetUserByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
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

		userSessionID, ok := data["userSessionId"].(float64)
		if !ok || userSessionID == 0 {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		// Whether the row being deleted is the caller's own is a field on that row. The auth
		// server computes isCurrent from the sid claim of the very token this request forwards,
		// so this is the same comparison the console used to make for itself, now made once and
		// in one place (#373).
		sessions, err := apiClient.GetUserSessionsByUserID(r.Context(), jwtInfo.TokenResponse.AccessToken, user.ID)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		isDeletingCurrentSession := false
		for _, es := range sessions {
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

		// Delete the user session via API
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
