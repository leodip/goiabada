package adminclienthandlers

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
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
)

func HandleAdminClientPermissionsGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("clientId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		client, err := database.GetClientById(nil, id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", id))))
			return
		}

		adminClientPermissions := struct {
			ClientId                 int64
			ClientIdentifier         string
			ClientCredentialsEnabled bool
			Permissions              map[int64]string
			IsSystemLevelClient      bool
		}{
			ClientId:                 client.Id,
			ClientIdentifier:         client.ClientIdentifier,
			ClientCredentialsEnabled: client.ClientCredentialsEnabled,
			Permissions:              make(map[int64]string),
			IsSystemLevelClient:      client.IsSystemLevelClient(),
		}

		err = database.ClientLoadPermissions(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.PermissionsLoadResources(nil, client.Permissions)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		for _, permission := range client.Permissions {

			res, err := database.GetResourceById(nil, permission.ResourceId)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			adminClientPermissions.Permissions[permission.Id] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}

		resources, err := database.GetAllResources(nil)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
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
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"client":            adminClientPermissions,
			"resources":         resources,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_permissions.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAdminClientPermissionsPost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	type permissionsPostInput struct {
		ClientId               int64   `json:"clientId"`
		AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		var data permissionsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		client, err := database.GetClientById(nil, data.ClientId)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		if client == nil {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", data.ClientId))))
			return
		}

		if client.IsSystemLevelClient() {
			httpHelper.JsonError(w, r, errors.WithStack(errors.New("trying to edit a system level client")))
			return
		}

		err = database.ClientLoadPermissions(nil, client)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.PermissionsLoadResources(nil, client.Permissions)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		for _, permissionId := range data.AssignedPermissionsIds {

			found := false
			for _, permission := range client.Permissions {
				if permission.Id == permissionId {
					found = true
					break
				}
			}

			if !found {
				permission, err := database.GetPermissionById(nil, permissionId)
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}
				if permission == nil {
					httpHelper.JsonError(w, r, errors.WithStack(errors.New("permission not found")))
					return
				}
				err = database.CreateClientPermission(nil, &models.ClientPermission{
					ClientId:     client.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					httpHelper.JsonError(w, r, err)
					return
				}
			}
		}

		toDelete := []int64{}
		for _, permission := range client.Permissions {
			found := false
			for _, permissionId := range data.AssignedPermissionsIds {
				if permission.Id == permissionId {
					found = true
					break
				}
			}

			if !found {
				toDelete = append(toDelete, permission.Id)
			}
		}

		for _, permissionId := range toDelete {

			clientPermission, err := database.GetClientPermissionByClientIdAndPermissionId(nil, client.Id, permissionId)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}

			if clientPermission == nil {
				httpHelper.JsonError(w, r, errors.WithStack(errors.New("client permission not found")))
				return
			}

			err = database.DeleteClientPermission(nil, clientPermission.Id)
			if err != nil {
				httpHelper.JsonError(w, r, err)
				return
			}
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedClientPermissions, map[string]interface{}{
			"clientId":     client.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		result := struct {
			Success bool
		}{
			Success: true,
		}
		httpHelper.EncodeJson(w, r, result)
	}
}
