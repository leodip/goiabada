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

// userConnectedClientsAPI is what the user's Connected clients tab needs: the user, the clients it
// is connected to, and the disconnect of one (#135 decisions 2 and 7).
type userConnectedClientsAPI interface {
	DisconnectUserClient(ctx context.Context, accessToken string, userID, clientID int64) error
	GetUserByID(ctx context.Context, accessToken string, userID int64) (*api.UserResponse, error)
	GetUserConnectedClients(ctx context.Context, accessToken string, userID int64) ([]api.ConnectedClientResponse, error)
}

// HandleConnectedClientsGet draws the user's Connected clients tab: every client the user is
// connected to, in the API's order.
func HandleConnectedClientsGet(
	httpHelper HTTPHelper,
	apiClient userConnectedClientsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

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

		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		user, err := apiClient.GetUserByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		clients, err := apiClient.GetUserConnectedClients(r.Context(), jwtInfo.TokenResponse.AccessToken, user.ID)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":    user,
			"clients": render.ConnectedClientInfos(clients),
			"page":    r.URL.Query().Get("page"),
			"query":   r.URL.Query().Get("query"),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_connected_clients.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// HandleConnectedClientsDisconnectPost disconnects the user in the path from the client a row's
// button names by its numeric id, for row-actions.js. The Admin API's DELETE is keyed by both, so
// it answers 404 for a user or client that does not exist and for a client the user no longer has
// anything with, which is a stale page and is answered as one (#135 decision 2).
func HandleConnectedClientsDisconnectPost(
	httpHelper HTTPHelper,
	apiClient userConnectedClientsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

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

		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		// The id decodes straight into an int64, so a fraction is refused rather than truncated
		// and a large id is not rounded to a neighbour's: either could name another client.
		var data struct {
			ClientID int64 `json:"clientId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil || data.ClientID <= 0 {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		if err := apiClient.DisconnectUserClient(r.Context(), jwtInfo.TokenResponse.AccessToken, id, data.ClientID); err != nil {
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
