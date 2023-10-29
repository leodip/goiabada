package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/entities"
)

func (s *Server) handleAdminClientPermissionsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "clientId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		client, err := s.database.GetClientById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if client == nil {
			s.internalServerError(w, r, errors.New("client not found"))
			return
		}

		adminClientPermissions := struct {
			ClientId                 uint
			ClientIdentifier         string
			ClientCredentialsEnabled bool
			Permissions              map[uint]string
			IsSystemLevelClient      bool
		}{
			ClientId:                 client.Id,
			ClientIdentifier:         client.ClientIdentifier,
			ClientCredentialsEnabled: client.ClientCredentialsEnabled,
			Permissions:              make(map[uint]string),
			IsSystemLevelClient:      client.IsSystemLevelClient(),
		}

		for _, permission := range client.Permissions {

			res, err := s.database.GetResourceById(permission.ResourceId)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			adminClientPermissions.Permissions[permission.Id] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}

		resources, err := s.database.GetAllResources()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sort.Slice(resources, func(i, j int) bool {
			return resources[i].ResourceIdentifier < resources[j].ResourceIdentifier
		})

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		clientPermissionsSavedSuccessfully := sess.Flashes("clientPermissionsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"client":                             adminClientPermissions,
			"resources":                          resources,
			"clientPermissionsSavedSuccessfully": len(clientPermissionsSavedSuccessfully) > 0,
			"csrfField":                          csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_clients_permissions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientPermissionsPost() http.HandlerFunc {

	type permissionsPostInput struct {
		ClientId               uint   `json:"clientId"`
		AssignedPermissionsIds []uint `json:"assignedPermissionsIds"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var data permissionsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		client, err := s.database.GetClientById(data.ClientId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if client == nil {
			s.jsonError(w, r, errors.New("client not found"))
			return
		}

		if client.IsSystemLevelClient() {
			s.jsonError(w, r, errors.New("trying to edit a system level client"))
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
				permission, err := s.database.GetPermissionById(permissionId)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
				if permission == nil {
					s.jsonError(w, r, errors.New("permission not found"))
					return
				}
				err = s.database.AddClientPermission(client.Id, permission.Id)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			}
		}

		toDelete := []uint{}
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
			err = s.database.DeleteClientPermission(client.Id, permissionId)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "clientPermissionsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAdminClientGetPermissionsGet() http.HandlerFunc {

	type getPermissionsResult struct {
		Permissions []entities.Permission
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := getPermissionsResult{}

		resourceIdStr := r.URL.Query().Get("resourceId")
		resourceId, err := strconv.ParseUint(resourceIdStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		permissions, err := s.database.GetResourcePermissions(uint(resourceId))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		result.Permissions = permissions
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
