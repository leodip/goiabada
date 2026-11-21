package adminuserhandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
)

// userAttributesEditAPI is what the edit user attribute page needs: the user, the attribute, and
// the write.
type userAttributesEditAPI interface {
	GetUserAttributeByID(ctx context.Context, accessToken string, attributeID int64) (*api.UserAttributeResponse, error)
	GetUserByID(ctx context.Context, accessToken string, userID int64) (*api.UserResponse, error)
	UpdateUserAttribute(ctx context.Context, accessToken string, attributeID int64, request *api.UpdateUserAttributeRequest) (*api.UserAttributeResponse, error)
}

func HandleAttributesEditGet(
	httpHelper HTTPHelper,
	apiClient userAttributesEditAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("userId")
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

		user, err := apiClient.GetUserByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		idStr = r.PathValue("attributeId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		attribute, err := apiClient.GetUserAttributeByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if attribute == nil || attribute.UserID != user.ID {
			httpHelper.NotFound(w, r)
			return
		}

		bind := map[string]interface{}{
			"user":            user,
			"attribute":       attribute,
			"storedAttribute": attribute,
			"page":            r.URL.Query().Get("page"),
			"query":           r.URL.Query().Get("query"),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAttributesEditPost(
	httpHelper HTTPHelper,
	apiClient userAttributesEditAPI,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("userId")
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

		user, err := apiClient.GetUserByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		idStr = r.PathValue("attributeId")
		if len(idStr) == 0 {
			httpHelper.NotFound(w, r)
			return
		}

		attributeID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.NotFound(w, r)
			return
		}

		attribute, err := apiClient.GetUserAttributeByID(r.Context(), jwtInfo.TokenResponse.AccessToken, attributeID)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if attribute == nil || attribute.UserID != user.ID {
			httpHelper.NotFound(w, r)
			return
		}

		// The attribute as stored names the page in its title, and the attribute below takes the
		// values submitted, for the inputs of a refused save drawn again (#562 decision 6).
		storedAttribute := *attribute

		// Update attribute fields with form values for potential error display
		attribute.Key = r.FormValue("attributeKey")
		attribute.Value = r.FormValue("attributeValue")
		attribute.IncludeInAccessToken = r.FormValue("includeInAccessToken") == "on"
		attribute.IncludeInIDToken = r.FormValue("includeInIdToken") == "on"

		renderError := func(message, errorField string) {
			bind := map[string]interface{}{
				"user":            user,
				"attribute":       attribute,
				"storedAttribute": &storedAttribute,
				"error":           message,
				"errorField":      errorField,
				"page":            r.URL.Query().Get("page"),
				"query":           r.URL.Query().Get("query"),
			}

			renderErr := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes_edit.html", bind)
			if renderErr != nil {
				httpHelper.InternalServerError(w, r, renderErr)
			}
		}

		if len(attribute.Key) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeAttributeKeyRequired, nil).Localize(r.Context()), "attributeKey")
			return
		}

		// Create update request for API
		request := &api.UpdateUserAttributeRequest{
			Key:                  attribute.Key,
			Value:                attribute.Value,
			IncludeInAccessToken: attribute.IncludeInAccessToken,
			IncludeInIDToken:     attribute.IncludeInIDToken,
		}

		_, err = apiClient.UpdateUserAttribute(r.Context(), jwtInfo.TokenResponse.AccessToken, attributeID, request)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderError(message, render.ErrorField(err, render.AttributeErrorFields))
			})
			return
		}

		http.Redirect(w, r, withListPosition(baseURL, fmt.Sprintf("/admin/users/%v/attributes", user.ID), r), http.StatusFound)
	}
}
