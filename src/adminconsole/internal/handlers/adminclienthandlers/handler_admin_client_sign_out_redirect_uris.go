package adminclienthandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// clientSignOutRedirectURIsAPI is what the Sign-out redirect URIs page needs: the client, the
// global switches its gate reads against, and the write.
type clientSignOutRedirectURIsAPI interface {
	GetClientById(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, error)
	GetSettingsGeneral(ctx context.Context, accessToken string) (*api.SettingsGeneralResponse, error)
	UpdateClientPostLogoutRedirectURIs(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientPostLogoutRedirectURIsRequest) (*api.ClientResponse, error)
}

// HandleSignOutRedirectURIsGet draws a client's Sign-out redirect URIs tab: the addresses a
// sign-out may send the user back to, kept apart from its redirect URIs (#147 decision 6). It is
// gated as the Redirect URIs tab is, since a client that signs nobody in through a browser has no
// sign-out to return from.
func HandleSignOutRedirectURIsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientSignOutRedirectURIsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("clientId"), 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		clientResp, err := apiClient.GetClientById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		settingsResp, err := apiClient.GetSettingsGeneral(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		uris := make([]string, 0, len(clientResp.PostLogoutRedirectURIs))
		for _, uri := range clientResp.PostLogoutRedirectURIs {
			uris = append(uris, uri.URI)
		}
		sort.Strings(uris)

		client := struct {
			ClientId                     int64
			ClientIdentifier             string
			CanManageSignOutRedirectURIs bool
			SignOutRedirectURIs          []string
			IsSystemLevelClient          bool
			IsPublic                     bool
		}{
			ClientId:                     clientResp.Id,
			ClientIdentifier:             clientResp.ClientIdentifier,
			CanManageSignOutRedirectURIs: usesARedirectFlow(clientResp, settingsResp),
			SignOutRedirectURIs:          uris,
			IsSystemLevelClient:          clientResp.IsSystemLevelClient,
			IsPublic:                     clientResp.IsPublic,
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash("savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            client,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_sign_out_redirect_uris.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// HandleSignOutRedirectURIsPost saves the list the page sends, beside the list as the page loaded
// it, through the admin API, which refuses a save from an outdated page (#428).
func HandleSignOutRedirectURIsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientSignOutRedirectURIsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		var data SignOutRedirectURIsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		req := &api.UpdateClientPostLogoutRedirectURIsRequest{
			PostLogoutRedirectURIs:         data.SignOutRedirectURIs,
			ExpectedPostLogoutRedirectURIs: data.ExpectedSignOutRedirectURIs,
		}
		_, err = apiClient.UpdateClientPostLogoutRedirectURIs(r.Context(), jwtInfo.TokenResponse.AccessToken, data.ClientId, req)
		if err != nil {
			// The API's 400 names the entry it refused and why, and its 409 says the list changed
			// since the page loaded it: both are for the administrator to read (#122).
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.JSONError(w, r, err)
			return
		}

		sess.SetFlash("savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.JSONError(w, r, err)
			return
		}

		httpHelper.EncodeJSON(w, r, struct{ Success bool }{Success: true})
	}
}
