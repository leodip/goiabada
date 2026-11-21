package admingrouphandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
)

// groupAttributesAPI is what the group attributes page needs: the group, its attributes, and the
// delete of one.
type groupAttributesAPI interface {
	DeleteGroupAttribute(ctx context.Context, accessToken string, attributeID int64) error
	GetGroupAttributesByGroupID(ctx context.Context, accessToken string, groupID int64) ([]api.GroupAttributeResponse, error)
	GetGroupByID(ctx context.Context, accessToken string, groupID int64) (*api.GroupResponse, error)
}

func HandleAttributesGet(
	httpHelper HTTPHelper,
	apiClient groupAttributesAPI,
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

		// Get group via API
		group, err := apiClient.GetGroupByID(r.Context(), jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.NotFound(w, r)
			return
		}

		// Get group attributes via API
		attributes, err := apiClient.GetGroupAttributesByGroupID(r.Context(), jwtInfo.TokenResponse.AccessToken, group.ID)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"groupId":         group.ID,
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

func HandleAttributesRemovePost(
	httpHelper HTTPHelper,
	apiClient groupAttributesAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		attributeIDStr := r.PathValue("attributeId")
		if len(attributeIDStr) == 0 {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		attributeID, err := strconv.ParseInt(attributeIDStr, 10, 64)
		if err != nil {
			render.JSONNotFound(httpHelper, w, r)
			return
		}

		// Get JWT info from context to extract access token
		jwtInfo, ok := reqctx.JWTInfoFrom(r.Context())
		if !ok {
			httpHelper.JSONError(w, r, reqctx.ErrNoJWTInfo)
			return
		}

		// Delete group attribute via API (audit logging handled by AuthServer)
		err = apiClient.DeleteGroupAttribute(r.Context(), jwtInfo.TokenResponse.AccessToken, attributeID)
		if err != nil {
			render.HandleAPIErrorJSON(httpHelper, w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJSON(w, r, result)
	}
}
