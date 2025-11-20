package adminresourcehandlers

import (
    "net/http"

    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/pkg/errors"
)

func HandleAdminResourcesGet(
    httpHelper handlers.HttpHelper,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {

        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
            return
        }

        resources, err := apiClient.GetAllResources(jwtInfo.TokenResponse.AccessToken)
        if err != nil {
            handlers.HandleAPIError(httpHelper, w, r, err)
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
