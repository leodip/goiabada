package admingrouphandlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleAdminGroupPermissionsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
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

		// Get group and permissions via API
		group, groupPermissions, err := apiClient.GetGroupPermissions(jwtInfo.TokenResponse.AccessToken, id)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}
		if group == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		groupPermsDisplay := struct {
			GroupId         int64
			GroupIdentifier string
			Permissions     map[int64]string
		}{
			GroupId:         group.Id,
			GroupIdentifier: group.GroupIdentifier,
			Permissions:     make(map[int64]string),
		}

		for _, permission := range groupPermissions {
			groupPermsDisplay.Permissions[permission.Id] = permission.Resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}

		// Get all resources via API
		resources, err := apiClient.GetAllResources(jwtInfo.TokenResponse.AccessToken)
		if err != nil {
			handlers.HandleAPIError(httpHelper, w, r, err)
			return
		}

		sort.Slice(resources, func(i, j int) bool {
			return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
		})

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"group":             groupPermsDisplay,
			"resources":         resources,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminGroupPermissionsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var data PermissionsPostInput
		err = json.Unmarshal(body, &data)
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

		// Update group permissions via API (includes validation, security, and audit logging)
		updateReq := &api.UpdateGroupPermissionsRequest{
			PermissionIds: data.AssignedPermissionsIds,
		}

		err = apiClient.UpdateGroupPermissions(jwtInfo.TokenResponse.AccessToken, data.GroupId, updateReq)
		if err != nil {
			// Handle API errors by extracting the message for display
			if apiErr, ok := err.(*apiclient.APIError); ok {
				httpHelper.JsonError(w, r, fmt.Errorf("%s", apiErr.Message))
				return
			}
			httpHelper.JsonError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = httpSession.Save(r, w, sess)
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
