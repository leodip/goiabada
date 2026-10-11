package adminclienthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// clientDeleteAPI is what the client delete page needs: the permissions it warns about, and the
// delete.
type clientDeleteAPI interface {
	DeleteClient(ctx context.Context, accessToken string, clientId int64) error
	GetClientPermissions(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.PermissionResponse, error)
}

// clientDeleteView is what the delete page draws: the client, and the permissions it warns about.
type clientDeleteView struct {
	Id                       int64
	ClientIdentifier         string
	Description              string
	Enabled                  bool
	ConsentRequired          bool
	IsPublic                 bool
	IsSystemLevelClient      bool
	AuthorizationCodeEnabled bool
	ClientCredentialsEnabled bool
	Permissions              []api.PermissionResponse
}

func newClientDeleteView(client *api.ClientResponse, perms []api.PermissionResponse) clientDeleteView {
	return clientDeleteView{
		Id:                       client.Id,
		ClientIdentifier:         client.ClientIdentifier,
		Description:              client.Description,
		Enabled:                  client.Enabled,
		ConsentRequired:          client.ConsentRequired,
		IsPublic:                 client.IsPublic,
		IsSystemLevelClient:      client.IsSystemLevelClient,
		AuthorizationCodeEnabled: client.AuthorizationCodeEnabled,
		ClientCredentialsEnabled: client.ClientCredentialsEnabled,
		Permissions:              perms,
	}
}

func HandleDeleteGet(
	httpHelper HttpHelper,
	apiClient clientDeleteAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		client, perms, err := apiClient.GetClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		bind := map[string]interface{}{
			"client": newClientDeleteView(client, perms),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleDeletePost(
	httpHelper HttpHelper,
	apiClient clientDeleteAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		client, perms, err := apiClient.GetClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		if client.IsSystemLevelClient {
			httpHelper.InternalServerError(w, r, errs.New("cannot delete system level client"))
			return
		}

		// A refusal draws the page again from the view its first draw binds: the template reads the
		// permissions, which the API's client alone does not carry (#562).
		renderError := func(message string) {
			bind := map[string]interface{}{
				"client": newClientDeleteView(client, perms),
				"error":  message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		clientIdentifier := r.FormValue("clientIdentifier")
		if len(clientIdentifier) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeClientIdentifierRequired, nil).Localize(r.Context()))
			return
		}

		if client.ClientIdentifier != clientIdentifier {
			renderError(i18n.T(r.Context(), "adminconsole.refusal.client_delete.identifier_mismatch"))
			return
		}

		err = apiClient.DeleteClient(r.Context(), jwtInfo.TokenResponse.AccessToken, client.Id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", baseURL), http.StatusFound)
	}
}
