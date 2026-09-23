package admingrouphandlers

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

// groupAttributesAPI is what the group attributes page needs: the group, its attributes, and the
// delete of one.
type groupAttributesAPI interface {
	DeleteGroupAttribute(ctx context.Context, accessToken string, attributeId int64) error
	GetGroupAttributesByGroupId(ctx context.Context, accessToken string, groupId int64) ([]api.GroupAttributeResponse, error)
	GetGroupById(ctx context.Context, accessToken string, groupId int64) (*api.GroupResponse, error)
}

func HandleAdminGroupAttributesGet(
	httpHelper handlers.HttpHelper,
	apiClient groupAttributesAPI,
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

		// Get group attributes via API
		attributes, err := apiClient.GetGroupAttributesByGroupId(r.Context(), jwtInfo.TokenResponse.AccessToken, group.Id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"description":     group.Description,
			"attributes":      attributes,
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_attributes.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupAttributesRemovePost(
	httpHelper handlers.HttpHelper,
	apiClient groupAttributesAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

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

		// Get JWT info from context to extract access token
		jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauthclient.JwtInfo)
		if !ok {
			httpHelper.JsonError(w, r, errs.New("no JWT info found in context"))
			return
		}

		// Delete group attribute via API (audit logging handled by AuthServer)
		err = apiClient.DeleteGroupAttribute(r.Context(), jwtInfo.TokenResponse.AccessToken, attributeId)
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
