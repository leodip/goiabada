package server

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/pkg/errors"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminGroupDeleteGet() http.HandlerFunc {

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

		countOfUsers, err := s.databasev2.CountGroupMembers(nil, group.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"group":        group,
			"countOfUsers": countOfUsers,
			"csrfField":    csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_delete.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminGroupDeletePost() http.HandlerFunc {

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

		countOfUsers, err := s.databasev2.CountGroupMembers(nil, group.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"group":        group,
				"countOfUsers": countOfUsers,
				"error":        message,
				"csrfField":    csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_delete.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		groupIdentifier := r.FormValue("groupIdentifier")
		if len(groupIdentifier) == 0 {
			renderError("Group identifier is required.")
			return
		}

		if group.GroupIdentifier != groupIdentifier {
			renderError("Group identifier does not match the group being deleted.")
			return
		}

		err = s.databasev2.DeleteGroup(nil, group.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditDeletedGroup, map[string]interface{}{
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"loggedInUser":    s.getLoggedInSubject(r),
		})

		http.Redirect(w, r, fmt.Sprintf("%v/admin/groups", lib.GetBaseUrl()), http.StatusFound)
	}
}
