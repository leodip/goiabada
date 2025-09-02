package adminuserhandlers

import (
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminUserAttributesGet(
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

		attributes, err := apiClient.GetUserAttributesByUserId(jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":       user,
			"attributes": attributes,
			"page":       r.URL.Query().Get("page"),
			"query":      r.URL.Query().Get("query"),
			"csrfField":  csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_attributes.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserAttributesRemovePost(
	httpHelper handlers.HttpHelper,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
			return
		}

		user, err := apiClient.GetUserById(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		attributes, err := apiClient.GetUserAttributesByUserId(jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		attributeIdStr := chi.URLParam(r, "attributeId")
		if len(attributeIdStr) == 0 {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("attribute id is required")))
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		found := false
		for _, attribute := range attributes {
			if attribute.Id == attributeId {
				found = true
				break
			}
		}

		if !found {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("attribute not found")))
			return
		}

		err = apiClient.DeleteUserAttribute(jwtInfo.TokenResponse.AccessToken, attributeId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
