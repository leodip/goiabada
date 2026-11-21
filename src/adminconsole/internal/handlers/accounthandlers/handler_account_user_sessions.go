package accounthandlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// accountSessionsAPI is what the account sessions page needs: the list, and the revoke of one.
type accountSessionsAPI interface {
	DeleteAccountSession(ctx context.Context, accessToken string, sessionID int64) error
	GetAccountSessions(ctx context.Context, accessToken string) ([]api.UserSessionDetailResponse, error)
}

func HandleSessionsGet(
	httpHelper HTTPHelper,
	apiClient accountSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		// Fetch sessions via API
		sessions, err := apiClient.GetAccountSessions(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sessionInfoArr := render.SessionInfos(sessions)

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

func HandleSessionsEndSessionPost(
	httpHelper HTTPHelper,
	apiClient accountSessionsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		var data map[string]interface{}
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&data); err != nil {
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
		sessions, err := apiClient.GetAccountSessions(r.Context(), jwtInfo.TokenResponse.AccessToken)
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
			}{Success: true, IsCurrentSession: true}
			httpHelper.EncodeJSON(w, r, result)
			return
		}

		// Delete session via API (server validates ownership and audits)
		if err = apiClient.DeleteAccountSession(r.Context(), jwtInfo.TokenResponse.AccessToken, int64(userSessionID)); err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct{ Success bool }{Success: true}
		httpHelper.EncodeJSON(w, r, result)
	}
}
