package adminclienthandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/config"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// clientDeleteAPI is what the client delete page needs: the permissions it warns about, and the
// delete.
type clientDeleteAPI interface {
	DeleteClient(ctx context.Context, accessToken string, clientId int64) error
	GetClientPermissions(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.PermissionResponse, error)
}

func HandleAdminClientDeleteGet(
	httpHelper handlers.HttpHelper,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		client, perms, err := apiClient.GetClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if client == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Build a view model including permissions for template compatibility
		view := struct {
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
		}{
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

		bind := map[string]interface{}{
			"client": view,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientDeletePost(
	httpHelper handlers.HttpHelper,
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		client, _, err := apiClient.GetClientPermissions(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
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

		renderError := func(message string) {
			bind := map[string]interface{}{
				"client": client,
				"error":  message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_delete.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		clientIdentifier := r.FormValue("clientIdentifier")
		if len(clientIdentifier) == 0 {
			renderError("Client identifier is required.")
			return
		}

		if client.ClientIdentifier != clientIdentifier {
			renderError("Client identifier does not match the client being deleted.")
			return
		}

		err = apiClient.DeleteClient(r.Context(), jwtInfo.TokenResponse.AccessToken, client.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/clients", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
