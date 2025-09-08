package adminresourcehandlers

import (
    "fmt"
    "net/http"
    "strings"

    "github.com/gorilla/csrf"
    "github.com/leodip/goiabada/adminconsole/internal/apiclient"
    "github.com/leodip/goiabada/adminconsole/internal/handlers"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/config"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/oauth"
    "github.com/pkg/errors"
)

func HandleAdminResourceNewGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminResourceNewPost(
    httpHelper handlers.HttpHelper,
    apiClient apiclient.ApiClient,
) http.HandlerFunc {

    return func(w http.ResponseWriter, r *http.Request) {

        renderError := func(message string) {
            bind := map[string]interface{}{
                "error":              message,
                "resourceIdentifier": r.FormValue("resourceIdentifier"),
                "description":        r.FormValue("description"),
                "csrfField":          csrf.TemplateField(r),
            }

            err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_resources_new.html", bind)
            if err != nil {
                httpHelper.InternalServerError(w, r, err)
            }
        }

        // Get JWT info from context to extract access token
        jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
        if !ok {
            httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
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

        _, err := apiClient.CreateResource(jwtInfo.TokenResponse.AccessToken, req)
        if err != nil {
            if apiErr, ok := err.(*apiclient.APIError); ok {
                renderError(apiErr.Message)
                return
            }
            httpHelper.InternalServerError(w, r, err)
            return
        }

        http.Redirect(w, r, fmt.Sprintf("%v/admin/resources", config.GetAdminConsole().BaseURL), http.StatusFound)
    }
}
