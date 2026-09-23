package admingrouphandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// groupAttributesAddAPI is what the add group attribute page needs: the group it belongs to, and
// the create.
type groupAttributesAddAPI interface {
	CreateGroupAttribute(ctx context.Context, accessToken string, request *api.CreateGroupAttributeRequest) (*api.GroupAttributeResponse, error)
	GetGroupById(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, error)
}

func HandleAdminGroupAttributesAddGet(
	httpHelper handlers.HttpHelper,
	apiClient groupAttributesAddAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get group via API
		group, err := apiClient.GetGroupById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.NotFound(w, r)
			return
		}

		bind := map[string]interface{}{
			"groupId":              group.Id,
			"groupIdentifier":      group.GroupIdentifier,
			"includeInAccessToken": true,
			"includeInIdToken":     true,
			"description":          group.Description,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupAttributesAddPost(
	httpHelper handlers.HttpHelper,
	apiClient groupAttributesAddAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
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
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get group via API
		group, err := apiClient.GetGroupById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.NotFound(w, r)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"groupId":              group.Id,
				"groupIdentifier":      group.GroupIdentifier,
				"attributeKey":         r.FormValue("attributeKey"),
				"attributeValue":       r.FormValue("attributeValue"),
				"includeInAccessToken": r.FormValue("includeInAccessToken") == "on",
				"includeInIdToken":     r.FormValue("includeInIdToken") == "on",
				"error":                message,
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		attrKey := r.FormValue("attributeKey")
		attrValue := r.FormValue("attributeValue")
		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"
		includeInIdToken := r.FormValue("includeInIdToken") == "on"

		// Create group attribute via API (validation handled by AuthServer)
		createReq := &api.CreateGroupAttributeRequest{
			Key:                  attrKey,
			Value:                attrValue,
			IncludeInAccessToken: includeInAccessToken,
			IncludeInIdToken:     includeInIdToken,
			GroupId:              group.Id,
		}

		_, err = apiClient.CreateGroupAttribute(r.Context(), jwtInfo.TokenResponse.AccessToken, createReq)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/admin/groups/%v/attributes", group.Id), http.StatusFound)
	}
}
