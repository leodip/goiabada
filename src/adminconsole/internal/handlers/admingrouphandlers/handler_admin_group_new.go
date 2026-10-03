package admingrouphandlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

func HandleAdminGroupNewGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		bind := map[string]interface{}{}

		err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

// groupNewAPI is what the new group page needs: the one write it makes.
type groupNewAPI interface {
	CreateGroup(ctx context.Context, accessToken string, request *api.CreateGroupRequest) (*api.GroupResponse, error)
}

func HandleAdminGroupNewPost(
	httpHelper HttpHelper,
	apiClient groupNewAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":           message,
				"groupIdentifier": r.FormValue("groupIdentifier"),
				"description":     r.FormValue("description"),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_new.html", bind)
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
		_, err := apiClient.CreateGroup(r.Context(), jwtInfo.TokenResponse.AccessToken, createReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		// Redirect on success
		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups", baseURL), http.StatusFound)
	}
}
