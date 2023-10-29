package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminRoleDeleteGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "roleId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("roleId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		role, err := s.database.GetRoleById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if role == nil {
			s.internalServerError(w, r, errors.New("role not found"))
			return
		}

		countOfUsers, err := s.database.CountUsersInRole(role.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"role":         role,
			"countOfUsers": countOfUsers,
			"csrfField":    csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles_delete.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminRoleDeletePost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "roleId")
		if len(idStr) == 0 {
			s.internalServerError(w, r, errors.New("roleId is required"))
			return
		}

		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		role, err := s.database.GetRoleById(uint(id))
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if role == nil {
			s.internalServerError(w, r, errors.New("role not found"))
			return
		}

		countOfUsers, err := s.database.CountUsersInRole(role.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"role":         role,
				"countOfUsers": countOfUsers,
				"error":        message,
				"csrfField":    csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles_delete.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		roleIdentifier := r.FormValue("roleIdentifier")
		if len(roleIdentifier) == 0 {
			renderError("Role identifier is required.")
			return
		}

		if role.RoleIdentifier != roleIdentifier {
			renderError("Role identifier does not match the role being deleted.")
			return
		}

		err = s.database.DeleteRole(role.Id)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("%v/admin/roles", lib.GetBaseUrl()), http.StatusFound)
	}
}
