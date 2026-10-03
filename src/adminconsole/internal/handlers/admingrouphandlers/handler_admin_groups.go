package admingrouphandlers

import (
	"context"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// groupsAPI is what the groups list needs: the one read it renders.
type groupsAPI interface {
	GetAllGroups(ctx context.Context, accessToken string) ([]api.GroupResponse, error)
}

func HandleAdminGroupsGet(
	httpHelper HttpHelper,
	apiClient groupsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
			return
		}

		groups, err := apiClient.GetAllGroups(r.Context(), jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlerhelpers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groups": groups,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
