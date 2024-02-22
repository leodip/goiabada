package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminGroupMembersAddGet() http.HandlerFunc {

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

		bind := map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"description":     group.Description,
			"csrfField":       csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_members_add.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminGroupMembersSearchGet() http.HandlerFunc {

	type userResult struct {
		Id           int64
		Subject      string
		Username     string
		Email        string
		GivenName    string
		MiddleName   string
		FamilyName   string
		AddedToGroup bool
	}

	type searchResult struct {
		Users []userResult
	}

	return func(w http.ResponseWriter, r *http.Request) {
		result := searchResult{}

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
		group, err := s.databasev2.GetGroupById(nil, id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if group == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if len(query) == 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		users, _, err := s.databasev2.SearchUsersPaginated(nil, query, 1, 15)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		err = s.databasev2.UsersLoadGroups(nil, users)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		usersResult := make([]userResult, 0)
		for _, user := range users {

			userInGroup := false
			for _, userGroup := range user.Groups {
				if userGroup.Id == group.Id {
					userInGroup = true
					break
				}
			}

			usersResult = append(usersResult, userResult{
				Id:           user.Id,
				Subject:      user.Subject.String(),
				Username:     user.Username,
				Email:        user.Email,
				GivenName:    user.GivenName,
				MiddleName:   user.MiddleName,
				FamilyName:   user.FamilyName,
				AddedToGroup: userInGroup,
			})
		}

		result.Users = usersResult
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAdminGroupMembersAddPost() http.HandlerFunc {

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
		group, err := s.databasev2.GetGroupById(nil, id)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if group == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("group not found")))
			return
		}

		userIdStr := r.URL.Query().Get("userId")
		if len(userIdStr) == 0 {
			s.jsonError(w, r, errors.WithStack(errors.New("userId is required")))
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.databasev2.GetUserById(nil, userId)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		if user == nil {
			s.jsonError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		err = s.databasev2.CreateUserGroup(nil, &entitiesv2.UserGroup{
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

		result := struct {
			Success bool
		}{
			Success: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}
