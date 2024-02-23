package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminGroupMembersRemoveUserPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "groupId")
		if len(idStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("groupId is required")))
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		group, err := s.database.GetGroupById(nil, id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if group == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		userIdStr := chi.URLParam(r, "userId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.database.GetUserById(nil, userId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if user == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		userGroup, err := s.database.GetUserGroupByUserIdAndGroupId(nil, user.Id, group.Id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if userGroup == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("user not in group")))
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

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
