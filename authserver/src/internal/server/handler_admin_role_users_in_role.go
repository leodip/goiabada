package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/unknwon/paginater"
)

func (s *Server) handleAdminRoleUsersInRoleGet() http.HandlerFunc {

	type PageResult struct {
		Page     int
		PageSize int
		Total    int
		Users    []entities.User
	}

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

		page := r.URL.Query().Get("page")
		if len(page) == 0 {
			page = "1"
		}
		pageInt, err := strconv.Atoi(page)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		if pageInt < 1 {
			s.internalServerError(w, r, fmt.Errorf("invalid page %d", pageInt))
			return
		}

		const pageSize = 10
		users, total, err := s.database.GetUsersInRole(role.Id, pageInt, pageSize)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		pageResult := PageResult{
			Page:     pageInt,
			PageSize: pageSize,
			Total:    total,
			Users:    users,
		}

		p := paginater.New(total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"roleId":         role.Id,
			"roleIdentifier": role.RoleIdentifier,
			"pageResult":     pageResult,
			"paginator":      p,
			"description":    role.Description,
			"csrfField":      csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_roles_users_in_roles.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
