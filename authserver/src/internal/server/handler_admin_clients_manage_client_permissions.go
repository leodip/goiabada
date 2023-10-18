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
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientManageClientPermissionsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			if s.isLoggedIn(jwtInfo) {
				http.Redirect(w, r, lib.GetBaseUrl()+"/unauthorized", http.StatusFound)
				return
			} else {
				s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI, "openid authserver:admin-website")
				return
			}
		}

		idStr := chi.URLParam(r, "clientID")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("clientID is required"))
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

		adminClientPermissions := dtos.AdminClientPermissions{
			ClientID:                 client.ID,
			ClientIdentifier:         client.ClientIdentifier,
			ClientCredentialsEnabled: client.ClientCredentialsEnabled,
			Permissions:              make(map[uint]string),
		}

		for _, permission := range client.Permissions {

			res, err := s.database.GetResourceById(permission.ResourceID)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			adminClientPermissions.Permissions[permission.ID] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
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

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/admin_clients_permissions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminClientManageClientPermissionsPost() http.HandlerFunc {

	type permissionsPostInput struct {
		ClientID               uint   `json:"clientID"`
		AssignedPermissionsIds []uint `json:"assignedPermissionsIds"`
	}

	type permissionsPostResult struct {
		RequiresAuth      bool
		SavedSuccessfully bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := permissionsPostResult{
			RequiresAuth: true,
		}

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			result.RequiresAuth = false
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

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

		client, err := s.database.GetClientById(data.ClientID)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if client == nil {
			s.jsonError(w, r, errors.New("client not found"))
			return
		}

		for _, permissionID := range data.AssignedPermissionsIds {

			found := false
			for _, permission := range client.Permissions {
				if permission.ID == permissionID {
					found = true
					break
				}
			}

			if !found {
				permission, err := s.database.GetPermissionById(permissionID)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
				if permission == nil {
					s.jsonError(w, r, errors.New("permission not found"))
					return
				}
				err = s.database.AddClientPermission(client.ID, permission.ID)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			}
		}

		toDelete := []uint{}
		for _, permission := range client.Permissions {
			found := false
			for _, permissionID := range data.AssignedPermissionsIds {
				if permission.ID == permissionID {
					found = true
					break
				}
			}

			if !found {
				toDelete = append(toDelete, permission.ID)
			}
		}

		for _, permissionID := range toDelete {
			err = s.database.DeleteClientPermission(client.ID, permissionID)
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

		result.SavedSuccessfully = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handlePermissionsGet() http.HandlerFunc {

	type getPermissionsResult struct {
		RequiresAuth bool
		Permissions  []entities.Permission
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := getPermissionsResult{
			RequiresAuth: true,
		}

		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			result.RequiresAuth = false
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		resourceIDStr := r.URL.Query().Get("resourceID")
		resourceID, err := strconv.ParseUint(resourceIDStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		permissions, err := s.database.GetResourcePermissions(uint(resourceID))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		result.Permissions = permissions
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}