package adminuserhandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// userAttributesAPI is what the user attributes page needs: the user, its attributes, and the
// delete of one.
type userAttributesAPI interface {
	DeleteUserAttribute(ctx context.Context, accessToken string, attributeId int64) error
	GetUserAttributesByUserId(ctx context.Context, accessToken string, userId int64) ([]api.UserAttributeResponse, error)
	GetUserById(ctx context.Context, accessToken string, userId int64) (*api.UserResponse, error)
}

func HandleAdminUserAttributesGet(
	httpHelper handlers.HttpHelper,
	apiClient userAttributesAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
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

		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if user == nil {
			httpHelper.NotFound(w, r)
			return
		}

		attributes, err := apiClient.GetUserAttributesByUserId(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"user":       user,
			"attributes": attributes,
			"page":       r.URL.Query().Get("page"),
			"query":      r.URL.Query().Get("query"),
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
	apiClient userAttributesAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		user, err := apiClient.GetUserById(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}
		if user == nil {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		attributes, err := apiClient.GetUserAttributesByUserId(r.Context(), jwtInfo.TokenResponse.AccessToken, user.Id)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
			return
		}

		attributeIdStr := chi.URLParam(r, "attributeId")
		if len(attributeIdStr) == 0 {
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		attributeId, err := strconv.ParseInt(attributeIdStr, 10, 64)
		if err != nil {
			handlers.JsonNotFound(httpHelper, w, r)
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
			handlers.JsonNotFound(httpHelper, w, r)
			return
		}

		err = apiClient.DeleteUserAttribute(r.Context(), jwtInfo.TokenResponse.AccessToken, attributeId)
		if err != nil {
			handlers.HandleAPIErrorJson(httpHelper, w, r, err)
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
