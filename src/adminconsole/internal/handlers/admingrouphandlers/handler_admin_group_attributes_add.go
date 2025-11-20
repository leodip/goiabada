package admingrouphandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminGroupAttributesAddGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Get group via API
		group, _, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		bind := map[string]interface{}{
			"groupId":              group.Id,
			"groupIdentifier":      group.GroupIdentifier,
			"includeInAccessToken": true,
			"includeInIdToken":     true,
			"description":          group.Description,
			"csrfField":            csrf.TemplateField(r),
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
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		// Get group via API
		group, _, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
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
				"csrfField":            csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_add.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
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

		_, err = apiClient.CreateGroupAttribute(jwtInfo.TokenResponse.AccessToken, createReq)
		if err != nil {
			// Handle API errors by extracting the message for display
			if apiErr, ok := err.(*apiclient.APIError); ok {
				renderError(apiErr.Message)
				return
			}
			httpHelper.InternalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/admin/groups/%v/attributes", group.Id), http.StatusFound)
	}
}
