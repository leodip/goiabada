package adminuserhandlers

import (
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/unknwon/paginater"
)

func HandleAdminUsersGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

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
		users, total, err := database.SearchUsersPaginated(nil, query, pageInt, pageSize)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		pageResult := PageResult{
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

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_users.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
