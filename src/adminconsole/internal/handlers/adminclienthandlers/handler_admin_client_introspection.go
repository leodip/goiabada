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

// A client's introspection resources are the resources whose tokens it may introspect (#676
// decisions 5 and 14). The Introspection tab edits them as the Permissions tab edits a client's
// permissions: drawn as stored, changed in the page, and saved whole beside the list as drawn. A
// public client cannot authenticate, so it never introspects: its tab is left out of the tab bar,
// and reached by its address it says why and offers nothing to edit.

// clientIntrospectionAPI is what the Introspection tab needs: the resources to choose from, and the
// client's own list.
type clientIntrospectionAPI interface {
	GetAllResources(ctx context.Context, accessToken string) ([]api.ResourceResponse, error)
	GetClientIntrospectionResources(ctx context.Context, accessToken string, clientId int64) (*api.ClientResponse, []api.ResourceResponse, error)
	UpdateClientIntrospectionResources(ctx context.Context, accessToken string, clientId int64, request *api.UpdateClientIntrospectionResourcesRequest) error
}

func HandleIntrospectionGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientIntrospectionAPI,
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

		clientResp, listed, err := apiClient.GetClientIntrospectionResources(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if clientResp == nil {
			httpHelper.NotFound(w, r)
			return
		}

		adminClientIntrospection := struct {
			ClientId            int64
			ClientIdentifier    string
			IsPublic            bool
			IsSystemLevelClient bool
			Resources           []listedResource
		}{
			ClientId:            clientResp.Id,
			ClientIdentifier:    clientResp.ClientIdentifier,
			IsPublic:            clientResp.IsPublic,
			IsSystemLevelClient: clientResp.IsSystemLevelClient,
			Resources:           make([]listedResource, 0, len(listed)),
		}
		for _, resource := range listed {
			adminClientIntrospection.Resources = append(adminClientIntrospection.Resources, listedResource{
				Id:         resource.Id,
				Identifier: resource.ResourceIdentifier,
			})
		}
		sort.Slice(adminClientIntrospection.Resources, func(i, j int) bool {
			return adminClientIntrospection.Resources[i].Identifier < adminClientIntrospection.Resources[j].Identifier
		})

		// A public client is offered nothing to list, so its resources are not read.
		choices := []render.Choice{}
		if !clientResp.IsPublic {
			resources, getErr := apiClient.GetAllResources(r.Context(), jwtInfo.TokenResponse.AccessToken)
			if getErr != nil {
				render.HandleAPIError(httpHelper, w, r, getErr)
				return
			}
			sort.Slice(resources, func(i, j int) bool {
				return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
			})
			choices = render.ResourceChoices(resources)
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
			"client":            adminClientIntrospection,
			"resources":         choices,
			"savedSuccessfully": savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_introspection.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleIntrospectionPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient clientIntrospectionAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("clientId"), 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			render.JSONBadRequestBody(httpHelper, w, r)
			return
		}

		var data IntrospectionPostInput
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

		// Both lists pass through unchanged, the loaded one included, so the auth server refuses a
		// save from an outdated page and a list for a client made public since the page loaded.
		req := &api.UpdateClientIntrospectionResourcesRequest{
			ResourceIds:         data.ResourceIds,
			ExpectedResourceIds: data.ExpectedResourceIds,
		}
		if updateErr := apiClient.UpdateClientIntrospectionResources(r.Context(), jwtInfo.TokenResponse.AccessToken, id, req); updateErr != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, updateErr)
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

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJSON(w, r, result)
	}
}
