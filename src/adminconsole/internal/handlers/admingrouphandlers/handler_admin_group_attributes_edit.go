package admingrouphandlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminGroupAttributesEditGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		groupId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		attributeId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get group via API
		group, _, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, groupId)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get attribute via API
		attribute, err := apiClient.GetGroupAttributeById(jwtInfo.TokenResponse.AccessToken, attributeId)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if attribute == nil || attribute.GroupId != group.Id {
			httpHelper.NotFound(w, r)
			return
		}

		bind := map[string]interface{}{
			"group":     group,
			"attribute": attribute,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_edit.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupAttributesEditPost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		groupId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		attributeId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Get group via API for the redirect and error rendering
		group, _, err := apiClient.GetGroupById(jwtInfo.TokenResponse.AccessToken, groupId)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get current attribute for error rendering
		currentAttribute, err := apiClient.GetGroupAttributeById(jwtInfo.TokenResponse.AccessToken, attributeId)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if currentAttribute == nil || currentAttribute.GroupId != group.Id {
			httpHelper.NotFound(w, r)
			return
		}

		// Extract form values
		key := r.FormValue("attributeKey")
		value := r.FormValue("attributeValue")
		includeInAccessToken := r.FormValue("includeInAccessToken") == "on"
		includeInIdToken := r.FormValue("includeInIdToken") == "on"

		// Create a temporary attribute for error rendering
		tempAttribute := *currentAttribute
		tempAttribute.Key = key
		tempAttribute.Value = value
		tempAttribute.IncludeInAccessToken = includeInAccessToken
		tempAttribute.IncludeInIdToken = includeInIdToken

		renderError := func(message string) {
			bind := map[string]interface{}{
				"group":     group,
				"attribute": &tempAttribute,
				"error":     message,
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes_edit.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// Update group attribute via API (validation handled by AuthServer)
		updateReq := &api.UpdateGroupAttributeRequest{
			Key:                  key,
			Value:                value,
			IncludeInAccessToken: includeInAccessToken,
			IncludeInIdToken:     includeInIdToken,
		}

		_, err = apiClient.UpdateGroupAttribute(jwtInfo.TokenResponse.AccessToken, attributeId, updateReq)
		if err != nil {
			handlers.HandleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/admin/groups/%v/attributes", group.Id), http.StatusFound)
	}
}
