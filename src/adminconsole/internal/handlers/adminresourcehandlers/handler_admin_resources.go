package adminresourcehandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// resourcesAPI is what the resources list needs: the one read it renders.
type resourcesAPI interface {
	GetAllResources(ctx context.Context, accessToken string) ([]api.ResourceResponse, error)
}

func HandleAdminResourcesGet(
	httpHelper HttpHelper,
	apiClient resourcesAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		resources, err := apiClient.GetAllResources(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"resources": resources,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
