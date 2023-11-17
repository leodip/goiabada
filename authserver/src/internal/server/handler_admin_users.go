package server

import (
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/internal/entities"
	"github.com/unknwon/paginater"
)

func (s *Server) handleAdminUsersGet() http.HandlerFunc {

	type pageResult struct {
		Users    []entities.User
		Total    int
		Query    string
		Page     int
		PageSize int
	}

	return func(w http.ResponseWriter, r *http.Request) {

		page := r.URL.Query().Get("page")
		query := r.URL.Query().Get("query")

		pageInt, err := strconv.Atoi(page)
		if err != nil {
			pageInt = 1
		}
		if pageInt < 1 {
			pageInt = 1
		}

		const pageSize = 10
		users, total, err := s.database.SearchUsersPaginated(query, pageInt, pageSize)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		pageResult := pageResult{
			Users:    users,
			Total:    total,
			Query:    query,
			Page:     pageInt,
			PageSize: pageSize,
		}

		p := paginater.New(total, pageSize, pageInt, 5)

		bind := map[string]interface{}{
			"pageResult": pageResult,
			"paginator":  p,
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
