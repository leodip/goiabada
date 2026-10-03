package adminresourcehandlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

func HandleNewGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// resourceNewAPI is what the new resource page needs: the one write it makes.
type resourceNewAPI interface {
	CreateResource(ctx context.Context, accessToken string, request *api.CreateResourceRequest) (*api.ResourceResponse, error)
}

func HandleNewPost(
	httpHelper HttpHelper,
	apiClient resourceNewAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":              message,
				"resourceIdentifier": r.FormValue("resourceIdentifier"),
				"description":        r.FormValue("description"),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		// Parse form data
		resourceIdentifier := strings.TrimSpace(r.FormValue("resourceIdentifier"))
		description := strings.TrimSpace(r.FormValue("description"))

		// Build API request and call authserver
		req := &api.CreateResourceRequest{
			ResourceIdentifier: resourceIdentifier,
			Description:        description,
		}

		_, err := apiClient.CreateResource(r.Context(), jwtInfo.TokenResponse.AccessToken, req)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", baseURL), http.StatusFound)
	}
}
