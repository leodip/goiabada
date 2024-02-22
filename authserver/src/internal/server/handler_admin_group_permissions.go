package server

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminGroupPermissionsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		group, err := s.databasev2.GetGroupById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if group == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		err = s.databasev2.GroupLoadPermissions(nil, group)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		groupPermissions := struct {
			GroupId         int64
			GroupIdentifier string
			Permissions     map[int64]string
		}{
			GroupId:         group.Id,
			GroupIdentifier: group.GroupIdentifier,
			Permissions:     make(map[int64]string),
		}

		for _, permission := range group.Permissions {

			res, err := s.databasev2.GetResourceById(nil, permission.ResourceId)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			groupPermissions.Permissions[permission.Id] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
		}

		resources, err := s.databasev2.GetAllResources(nil)
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

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"group":             groupPermissions,
			"resources":         resources,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
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
		GroupId                int64   `json:"groupId"`
		AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
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

		group, err := s.databasev2.GetGroupById(nil, data.GroupId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if group == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		err = s.databasev2.GroupLoadPermissions(nil, group)
		if err != nil {
			s.internalServerError(w, r, err)
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
				permission, err := s.databasev2.GetPermissionById(nil, permissionId)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
				if permission == nil {
					s.jsonError(w, r, errors.WithStack(errors.New("permission not found")))
					return
				}

				err = s.databasev2.CreateGroupPermission(nil, &entitiesv2.GroupPermission{
					GroupId:      group.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					s.jsonError(w, r, err)
					return
				}

				lib.LogAudit(constants.AuditAddedGroupPermission, map[string]interface{}{
					"groupId":      group.Id,
					"permissionId": permission.Id,
					"loggedInUser": s.getLoggedInSubject(r),
				})
			}
		}

		toDelete := []int64{}
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

			groupPermission, err := s.databasev2.GetGroupPermissionByGroupIdAndPermissionId(nil, group.Id, permissionId)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			err = s.databasev2.DeleteGroupPermission(nil, groupPermission.Id)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditDeletedGroupPermission, map[string]interface{}{
				"groupId":      group.Id,
				"permissionId": permissionId,
				"loggedInUser": s.getLoggedInSubject(r),
			})
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		sess.AddFlash("true", "savedSuccessfully")
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
