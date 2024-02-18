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
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserPermissionsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.databasev2.GetUserById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, errors.New("user not found"))
			return
		}

		err = s.databasev2.UserLoadPermissions(nil, user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		userPermissions := make(map[int64]string)

		for _, permission := range user.Permissions {

			res, err := s.databasev2.GetResourceById(nil, permission.ResourceId)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			userPermissions[permission.Id] = res.ResourceIdentifier + ":" + permission.PermissionIdentifier
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
			"user":              user,
			"userPermissions":   userPermissions,
			"resources":         resources,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_permissions.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserPermissionsPost() http.HandlerFunc {

	type permissionsPostInput struct {
		AssignedPermissionsIds []int64 `json:"assignedPermissionsIds"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user, err := s.databasev2.GetUserById(nil, id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if user == nil {
			s.jsonError(w, r, errors.New("user not found"))
			return
		}

		err = s.databasev2.UserLoadPermissions(nil, user)
		if err != nil {
			s.jsonError(w, r, err)
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

		for _, permissionId := range data.AssignedPermissionsIds {

			found := false
			for _, permission := range user.Permissions {
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
					s.jsonError(w, r, errors.New("permission not found"))
					return
				}

				err = s.databasev2.CreateUserPermission(nil, &entitiesv2.UserPermission{
					UserId:       user.Id,
					PermissionId: permission.Id,
				})
				if err != nil {
					s.jsonError(w, r, err)
					return
				}

				lib.LogAudit(constants.AuditAddedUserPermission, map[string]interface{}{
					"userId":       user.Id,
					"permissionId": permission.Id,
					"loggedInUser": s.getLoggedInSubject(r),
				})
			}
		}

		toDelete := []int64{}
		for _, permission := range user.Permissions {
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

			userPermission, err := s.databasev2.GetUserPermissionByUserIdAndPermissionId(nil, user.Id, permissionId)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			err = s.databasev2.DeleteUserPermission(nil, userPermission.Id)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditDeletedUserPermission, map[string]interface{}{
				"userId":       user.Id,
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
