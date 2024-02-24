package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserGroupsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(nil, id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		err = s.database.UserLoadGroups(nil, user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		userGroups := make(map[int64]string)
		for _, grp := range user.Groups {
			userGroups[grp.Id] = grp.GroupIdentifier
		}

		allGroups, err := s.database.GetAllGroups(nil)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

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
			"userGroups":        userGroups,
			"allGroups":         allGroups,
			"page":              r.URL.Query().Get("page"),
			"query":             r.URL.Query().Get("query"),
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users_groups.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminUserGroupsPost() http.HandlerFunc {

	type groupsPostInput struct {
		AssignedGroupsIds []int64 `json:"assignedGroupsIds"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(nil, id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if user == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		var data groupsPostInput
		err = json.Unmarshal(body, &data)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		err = s.database.UserLoadGroups(nil, user)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		for _, groupId := range data.AssignedGroupsIds {

			found := false
			for _, grp := range user.Groups {
				if grp.Id == groupId {
					found = true
					break
				}
			}

			if !found {
				group, err := s.database.GetGroupById(nil, groupId)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
				if group == nil {
					s.jsonError(w, r, errors.WithStack(errors.New("group not found")))
					return
				}

				err = s.database.CreateUserGroup(nil, &entities.UserGroup{
					UserId:  user.Id,
					GroupId: group.Id,
				})
				if err != nil {
					s.jsonError(w, r, err)
					return
				}

				lib.LogAudit(constants.AuditUserAddedToGroup, map[string]interface{}{
					"userId":       user.Id,
					"groupId":      group.Id,
					"loggedInUser": s.getLoggedInSubject(r),
				})
			}
		}

		toDelete := []int64{}
		for _, grp := range user.Groups {
			found := false
			for _, grpId := range data.AssignedGroupsIds {
				if grp.Id == grpId {
					found = true
					break
				}
			}

			if !found {
				toDelete = append(toDelete, grp.Id)
			}
		}

		for _, grpId := range toDelete {

			group, err := s.database.GetGroupById(nil, grpId)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			userGroup, err := s.database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			err = s.database.DeleteUserGroup(nil, userGroup.Id)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			lib.LogAudit(constants.AuditUserRemovedFromGroup, map[string]interface{}{
				"userId":       user.Id,
				"groupId":      group.Id,
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
