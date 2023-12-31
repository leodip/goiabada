package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminUserGroupsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if user == nil {
			s.internalServerError(w, r, errors.New("user not found"))
			return
		}

		userGroups := make(map[uint]string)
		for _, grp := range user.Groups {
			userGroups[grp.Id] = grp.GroupIdentifier
		}

		allGroups, err := s.database.GetAllGroups()
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
		AssignedGroupsIds []uint `json:"assignedGroupsIds"`
	}

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "userId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.New("userId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user, err := s.database.GetUserById(uint(id))
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if user == nil {
			s.jsonError(w, r, errors.New("user not found"))
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

		for _, groupId := range data.AssignedGroupsIds {

			found := false
			for _, grp := range user.Groups {
				if grp.Id == groupId {
					found = true
					break
				}
			}

			if !found {
				group, err := s.database.GetGroupById(groupId)
				if err != nil {
					s.jsonError(w, r, err)
					return
				}
				if group == nil {
					s.jsonError(w, r, errors.New("group not found"))
					return
				}
				err = s.database.AddUserToGroup(user, group)
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

		toDelete := []uint{}
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

			group, err := s.database.GetGroupById(grpId)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			err = s.database.RemoveUserFromGroup(user, group)
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
