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

func (s *Server) handleAdminGroupMembersGet() http.HandlerFunc {

	type PageResult struct {
		Page     int
		PageSize int
		Total    int
		Users    []entities.User
	}

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
		users, total, err := s.database.GetGroupMembers(group.Id, pageInt, pageSize)
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
			"groupId":         group.Id,
			"groupIdentifier": group.GroupIdentifier,
			"pageResult":      pageResult,
			"paginator":       p,
			"description":     group.Description,
			"csrfField":       csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_groups_members.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
