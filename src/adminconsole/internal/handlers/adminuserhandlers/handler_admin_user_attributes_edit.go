package adminuserhandlers

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
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminUserAttributesEditGet(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
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

		user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attributeId is required")))
			return
		}

		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		attribute, err := apiClient.GetUserAttributeById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}
		if attribute == nil || attribute.UserId != user.Id {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attribute not found")))
			return
		}

		bind := map[string]interface{}{
			"user":      user,
			"attribute": attribute,
			"page":      r.URL.Query().Get("page"),
			"query":     r.URL.Query().Get("query"),
			"csrfField": csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAttributesEditPost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("userId is required")))
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

		user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		idStr = chi.URLParam(r, "attributeId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attributeId is required")))
			return
		}

		attributeId, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		attribute, err := apiClient.GetUserAttributeById(jwtInfo.TokenResponse.AccessToken, attributeId)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}
		if attribute == nil || attribute.UserId != user.Id {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("attribute not found")))
			return
		}

		// Update attribute fields with form values for potential error display
		attribute.Key = r.FormValue("attributeKey")
		attribute.Value = r.FormValue("attributeValue")
		attribute.IncludeInAccessToken = r.FormValue("includeInAccessToken") == "on"
		attribute.IncludeInIdToken = r.FormValue("includeInIdToken") == "on"

		renderError := func(message string) {
			bind := map[string]interface{}{
				"user":      user,
				"attribute": attribute,
				"error":     message,
				"page":      r.URL.Query().Get("page"),
				"query":     r.URL.Query().Get("query"),
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		if len(attribute.Key) == 0 {
			renderError("Attribute key is required")
			return
		}

		// Create update request for API
		request := &api.UpdateUserAttributeRequest{
			Key:                  attribute.Key,
			Value:                attribute.Value,
			IncludeInAccessToken: attribute.IncludeInAccessToken,
			IncludeInIdToken:     attribute.IncludeInIdToken,
		}

		_, err = apiClient.UpdateUserAttribute(jwtInfo.TokenResponse.AccessToken, attributeId, request)
		if err != nil {
			handleAPIErrorWithCallback(httpHelper, w, r, err, renderError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/users/%v/attributes?page=%v&query=%v", config.GetAdminConsole().BaseURL, user.Id,
			r.URL.Query().Get("page"), r.URL.Query().Get("query")), http.StatusFound)
	}
}
