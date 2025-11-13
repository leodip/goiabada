package adminuserhandlers

import (
	"encoding/json"
	"io"
	"net/http"
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

func HandleAdminUserPermissionsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
			// Get JWT info from context to extract access token
			jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
			if !ok {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
				return
			}
			accessToken := jwtInfo.TokenResponse.AccessToken

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

			// Get user permissions via API
			user, userPermissions, err := apiClient.GetUserPermissions(accessToken, id)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if user == nil {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
				return
			}

			// Create permission display map for template
			permissionDisplayMap := make(map[int64]string)
			for _, permission := range userPermissions {
				permissionDisplayMap[permission.Id] = permission.Resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
			}

			// Get all resources via API
			resources, err := apiClient.GetAllResources(accessToken)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// Resources are already sorted in the API response

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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
			"user":              user,
			"userPermissions":   permissionDisplayMap,
			"resources":         resources,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminUserPermissionsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	apiClient apiclient.ApiClient,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
			// Get JWT info from context to extract access token
			jwtInfo, ok := r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
			if !ok {
				httpHelper.JsonError(w, r, errors.WithStack(errors.New("no JWT info found in context")))
				return
			}
			accessToken := jwtInfo.TokenResponse.AccessToken

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

			// Convert to API request format
			request := &api.UpdateUserPermissionsRequest{
				PermissionIds: data.AssignedPermissionsIds,
			}

			// Update user permissions via API (includes validation and audit logging)
			err = apiClient.UpdateUserPermissions(accessToken, id, request)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

		sess, err := httpSession.Get(r, constants.AdminConsoleSessionName)
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
