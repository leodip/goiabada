package admingrouphandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// groupSettingsAPI is what the group settings page needs: the group, and the write.
type groupSettingsAPI interface {
	GetGroupByID(ctx context.Context, accessToken string, groupID int64) (*api.GroupResponse, error)
	UpdateGroup(ctx context.Context, accessToken string, groupID int64, request *api.UpdateGroupRequest) (*api.GroupResponse, error)
}

func HandleSettingsGet(
	httpHelper HTTPHelper,
	httpSession sessionstore.Store,
	apiClient groupSettingsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("groupId")
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
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		group, err := apiClient.GetGroupByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		_, savedSuccessfully := sess.TakeFlash(r.URL.Path, "savedSuccessfully")
		if savedSuccessfully {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"groupId":              group.ID,
			"storedGroup":          group,
			"groupIdentifier":      group.GroupIdentifier,
			"description":          group.Description,
			"includeInIdToken":     group.IncludeInIDToken,
			"includeInAccessToken": group.IncludeInAccessToken,
			"savedSuccessfully":    savedSuccessfully,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_settings.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleSettingsPost(
	httpHelper HTTPHelper,
	httpSession sessionstore.Store,
	apiClient groupSettingsAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("groupId")
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
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.InternalServerError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		// The group as stored, which a refused save is drawn with: the page title and the original
		// identifier the rename question compares against stand for the group as it is, so the same
		// rename attempted again is asked again (#562 decision 6).
		group, err := apiClient.GetGroupByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		// Parse form data
		groupIdentifier := strings.TrimSpace(r.FormValue("groupIdentifier"))
		description := strings.TrimSpace(r.FormValue("description"))
		includeInIDToken := r.FormValue("includeInIdToken") == "on"
		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"

		renderError := func(message, errorField string) {
			bind := map[string]interface{}{
				"groupId":              group.ID,
				"storedGroup":          group,
				"groupIdentifier":      groupIdentifier,
				"description":          description,
				"includeInIdToken":     includeInIDToken,
				"includeInAccessToken": includeInAccessToken,
				"error":                message,
				"errorField":           errorField,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_settings.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		// Create API request
		updateReq := &api.UpdateGroupRequest{
			GroupIdentifier:      groupIdentifier,
			Description:          description,
			IncludeInIDToken:     includeInIDToken,
			IncludeInAccessToken: includeInAccessToken,
		}

		// Call API to update group
		_, err = apiClient.UpdateGroup(r.Context(), jwtInfo.TokenResponse.AccessToken, id, updateReq)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, groupErrorFields))
			})
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		pagePath := fmt.Sprintf("/admin/groups/%v/settings", id)
		sess.SetFlash(pagePath, "savedSuccessfully", "true")
		err = httpSession.Save(r, w, sess)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, baseURL+pagePath, http.StatusFound)
	}
}
