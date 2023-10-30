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
)

func (s *Server) handleAdminGroupPermissionsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("groupId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		group, err := s.database.GetGroupById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if group == nil {
			s.internalServerError(w, r, errors.New("group not found"))
			return
		}

		groupPermissions := struct {
			GroupId         uint
			GroupIdentifier string
			Permissions     map[uint]string
		}{
			GroupId:         group.Id,
			GroupIdentifier: group.GroupIdentifier,
			Permissions:     make(map[uint]string),
		}

		for _, permission := range group.Permissions {

			res, err := s.database.GetResourceById(permission.ResourceId)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			groupPermissions.Permissions[permission.Id] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
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

		groupPermissionsSavedSuccessfully := sess.Flashes("groupPermissionsSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"group":                             groupPermissions,
			"resources":                         resources,
			"groupPermissionsSavedSuccessfully": len(groupPermissionsSavedSuccessfully) > 0,
			"csrfField":                         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_permissions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminGroupPermissionsPost() http.HandlerFunc {

	type permissionsPostInput struct {
		GroupId                uint   `json:"groupId"`
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

		group, err := s.database.GetGroupById(data.GroupId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if group == nil {
			s.jsonError(w, r, errors.New("group not found"))
			return
		}

		for _, permissionId := range data.AssignedPermissionsIds {

			found := false
			for _, permission := range group.Permissions {
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
				err = s.database.AddGroupPermission(group.Id, permission.Id)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
			}
		}

		toDelete := []uint{}
		for _, permission := range group.Permissions {
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
			err = s.database.DeleteGroupPermission(group.Id, permissionId)
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

		sess.AddFlash("true", "groupPermissionsSavedSuccessfully")
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
