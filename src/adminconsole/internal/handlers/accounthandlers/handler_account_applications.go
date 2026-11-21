package accounthandlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// accountApplicationsAPI is what the Applications page needs: the user's connected clients, and the
// disconnect of one (#135 decisions 2 and 7).
type accountApplicationsAPI interface {
	GetAccountConnectedClients(ctx context.Context, accessToken string) ([]api.ConnectedClientResponse, error)
	DisconnectAccountClient(ctx context.Context, accessToken string, clientID int64) error
}

// HandleApplicationsGet draws the Applications page: every client the user is connected to, in the
// API's order.
func HandleApplicationsGet(
	httpHelper HTTPHelper,
	apiClient accountApplicationsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		clients, err := apiClient.GetAccountConnectedClients(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"clients": render.ConnectedClientInfos(clients),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_applications.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// HandleApplicationsDisconnectPost disconnects the client a row's button names by its numeric id,
// for row-actions.js. The page offers no button for the console itself (decision 5), and the
// auth server answers whether there was anything to end.
func HandleApplicationsDisconnectPost(
	httpHelper HTTPHelper,
	apiClient accountApplicationsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
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

		if err := apiClient.DisconnectAccountClient(r.Context(), jwtInfo.TokenResponse.AccessToken, data.ClientID); err != nil {
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
