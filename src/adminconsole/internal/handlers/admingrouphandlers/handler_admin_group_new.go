package admingrouphandlers

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

func HandleAdminGroupNewGet(
	httpHelper handlers.HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{
			"csrfField": csrf.TemplateField(r),
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupNewPost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":           message,
				"groupIdentifier": r.FormValue("groupIdentifier"),
				"description":     r.FormValue("description"),
				"csrfField":       csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
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
		groupIdentifier := strings.TrimSpace(r.FormValue("groupIdentifier"))
		description := strings.TrimSpace(r.FormValue("description"))
		includeInIdToken := r.FormValue("includeInIdToken") == "on"
		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"

		// Create API request
		createReq := &api.CreateGroupRequest{
			GroupIdentifier:      groupIdentifier,
			Description:          description,
			IncludeInIdToken:     includeInIdToken,
			IncludeInAccessToken: includeInAccessToken,
		}

		// Call API to create group
		_, err := apiClient.CreateGroup(jwtInfo.TokenResponse.AccessToken, createReq)
		if err != nil {
			if apiErr, ok := err.(*apiclient.APIError); ok {
				// Show validation errors from API
				renderError(apiErr.Message)
				return
			}
			// Handle other errors
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Redirect on success
		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups", config.GetAdminConsole().BaseURL), http.StatusFound)
	}
}
